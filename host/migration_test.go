package provisioner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMigrationPlanIsGuardedAndDefinesRollback(t *testing.T) {
	config := MigrationConfig{
		StandardPackageAID:  StandardPackageAIDHex,
		StandardInstanceAID: StandardInstanceAIDHex,
		CanaryPackageAID:    "A00000015141434D",
		CanaryInstanceAID:   "A00000015141434D00",
		Rollback:            testArtifactSpec("rollback.cap", 'a', StandardPackageAIDHex, StandardInstanceAIDHex),
		Canary:              testArtifactSpec("canary.cap", 'c', "A00000015141434D", "A00000015141434D00"),
		Release:             testArtifactSpec("multi-rule.cap", 'b', StandardPackageAIDHex, StandardInstanceAIDHex),
		CanaryEvidencePath:  "canary-evidence.json",
		ExportPath:          "secure-exported-v0.1.1-rule.json",
	}

	plan, err := PlanMigration(config)
	if err != nil {
		t.Fatalf("PlanMigration: %v", err)
	}
	want := []MigrationStage{
		MigrationExportCurrent,
		MigrationVerifyRollbackArtifact,
		MigrationVerifyCanaryEvidence,
		MigrationVerifyReleaseArtifact,
		MigrationGuardMaintenance,
		MigrationDeleteStandard,
		MigrationInstallRelease,
		MigrationRestoreExportedFirst,
		MigrationReconcileDesired,
		MigrationVerifyRelease,
	}
	if !reflect.DeepEqual(plan.Forward, want) {
		t.Fatalf("forward stages = %v, want %v", plan.Forward, want)
	}
	rollbackWant := []MigrationStage{
		MigrationDeletePartial,
		MigrationInstallRollback,
		MigrationRestoreExportedRollback,
		MigrationVerifyRollback,
	}
	if !reflect.DeepEqual(plan.Rollback, rollbackWant) {
		t.Fatalf("rollback stages = %v, want %v", plan.Rollback, rollbackWant)
	}
}

func TestMigrationExecutionRollsBackAfterStandardDeletionFailure(t *testing.T) {
	operations := &recordingMigrationOps{failAt: MigrationInstallRelease}
	executor := MigrationExecutor{Operations: operations}
	config := validMigrationConfig()

	if _, err := executor.Execute(context.Background(), config, true, MaintenanceAcknowledgement(config)); err == nil {
		t.Fatal("Execute unexpectedly succeeded")
	}
	wantSuffix := []MigrationStage{
		MigrationDeletePartial,
		MigrationInstallRollback,
		MigrationRestoreExportedRollback,
		MigrationVerifyRollback,
	}
	if len(operations.calls) < len(wantSuffix) {
		t.Fatalf("calls = %v", operations.calls)
	}
	gotSuffix := operations.calls[len(operations.calls)-len(wantSuffix):]
	if !reflect.DeepEqual(gotSuffix, wantSuffix) {
		t.Fatalf("rollback suffix = %v, want %v", gotSuffix, wantSuffix)
	}
}

func TestMigrationExecutionUsesIndependentBoundedContextForRollback(t *testing.T) {
	forwardContext, cancelForward := context.WithCancel(context.Background())
	operations := &cancelingMigrationOps{cancelForward: cancelForward}
	executor := MigrationExecutor{Operations: operations, RecoveryTimeout: time.Second}
	config := validMigrationConfig()

	result, err := executor.Execute(forwardContext, config, true, MaintenanceAcknowledgement(config))
	if err == nil {
		t.Fatal("Execute unexpectedly succeeded")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute error = %v, want context cancellation cause", err)
	}
	if !result.RolledBack {
		t.Fatalf("Execute reported rollback failure: %v", err)
	}
	wantSuffix := []MigrationStage{
		MigrationDeletePartial,
		MigrationInstallRollback,
		MigrationRestoreExportedRollback,
		MigrationVerifyRollback,
	}
	if len(operations.calls) < len(wantSuffix) {
		t.Fatalf("calls = %v", operations.calls)
	}
	gotSuffix := operations.calls[len(operations.calls)-len(wantSuffix):]
	if !reflect.DeepEqual(gotSuffix, wantSuffix) {
		t.Fatalf("rollback suffix = %v, want %v", gotSuffix, wantSuffix)
	}
	if operations.boundedRollbackCalls != len(wantSuffix) {
		t.Fatalf("bounded rollback calls = %d, want %d", operations.boundedRollbackCalls, len(wantSuffix))
	}
}

func TestMigrationDryRunHasNoSideEffects(t *testing.T) {
	operations := &recordingMigrationOps{}
	executor := MigrationExecutor{Operations: operations}
	result, err := executor.Execute(context.Background(), validMigrationConfig(), false, "")
	if err != nil {
		t.Fatalf("Execute dry-run: %v", err)
	}
	if result.Executed || len(operations.calls) != 0 {
		t.Fatalf("dry-run executed=%v calls=%v", result.Executed, operations.calls)
	}
}

func TestMigrationConfigPinsArtifactIdentitiesAndExportPath(t *testing.T) {
	config := validMigrationConfig()
	config.Release.AppletAID = config.CanaryInstanceAID
	if _, err := PlanMigration(config); err == nil {
		t.Fatal("PlanMigration accepted a release artifact for the canary identity")
	}

	config = validMigrationConfig()
	config.ExportPath = ""
	if _, err := PlanMigration(config); err == nil {
		t.Fatal("PlanMigration accepted a missing secure export path")
	}
}

type recordingMigrationOps struct {
	calls  []MigrationStage
	failAt MigrationStage
}

func (r *recordingMigrationOps) RunStage(_ context.Context, stage MigrationStage, _ MigrationConfig) error {
	r.calls = append(r.calls, stage)
	if stage == r.failAt {
		return errors.New("simulated migration failure")
	}
	return nil
}

type cancelingMigrationOps struct {
	cancelForward        context.CancelFunc
	calls                []MigrationStage
	boundedRollbackCalls int
}

func (o *cancelingMigrationOps) RunStage(ctx context.Context, stage MigrationStage, _ MigrationConfig) error {
	o.calls = append(o.calls, stage)
	if stage == MigrationInstallRelease {
		o.cancelForward()
		return context.Canceled
	}
	switch stage {
	case MigrationDeletePartial, MigrationInstallRollback, MigrationRestoreExportedRollback, MigrationVerifyRollback:
		if err := ctx.Err(); err != nil {
			return errors.New("rollback received canceled forward context")
		}
		if _, bounded := ctx.Deadline(); !bounded {
			return errors.New("rollback context has no deadline")
		}
		o.boundedRollbackCalls++
	}
	return nil
}

func validMigrationConfig() MigrationConfig {
	return MigrationConfig{
		StandardPackageAID:  StandardPackageAIDHex,
		StandardInstanceAID: StandardInstanceAIDHex,
		CanaryPackageAID:    "A00000015141434D",
		CanaryInstanceAID:   "A00000015141434D00",
		Rollback:            testArtifactSpec("rollback.cap", 'a', StandardPackageAIDHex, StandardInstanceAIDHex),
		Canary:              testArtifactSpec("canary.cap", 'c', "A00000015141434D", "A00000015141434D00"),
		Release:             testArtifactSpec("multi-rule.cap", 'b', StandardPackageAIDHex, StandardInstanceAIDHex),
		CanaryEvidencePath:  "canary-evidence.json",
		ExportPath:          "secure-exported-v0.1.1-rule.json",
	}
}

func testArtifactSpec(path string, digestByte byte, packageAID, appletAID string) ArtifactSpec {
	return ArtifactSpec{
		Path:                  path,
		SHA256:                stringsOf(digestByte, 64),
		PackageAID:            packageAID,
		AppletAID:             appletAID,
		SignaturePath:         path + ".sig",
		PublicKeyPath:         "release-signing.pub",
		ToolchainManifestPath: path + ".toolchain.json",
	}
}

func stringsOf(value byte, count int) string {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return string(result)
}
