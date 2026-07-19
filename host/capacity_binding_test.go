package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDesiredCapacityMatchesThePinnedBuild(t *testing.T) {
	spec := pinnedReleaseArtifact(t, t.TempDir(), 16, 64)
	if err := VerifyDesiredCapacity(spec, 16); err != nil {
		t.Fatalf("VerifyDesiredCapacity: %v", err)
	}
}

func TestVerifyDesiredCapacityRefusesADisagreeingManifest(t *testing.T) {
	spec := pinnedReleaseArtifact(t, t.TempDir(), 16, 64)
	err := VerifyDesiredCapacity(spec, 24)
	if err == nil {
		t.Fatal("VerifyDesiredCapacity accepted a capacity the pinned CAP was not built with")
	}
	// The operator has to see both numbers to know which side is wrong.
	if !strings.Contains(err.Error(), "24") || !strings.Contains(err.Error(), "16") {
		t.Fatalf("error does not name both capacities: %v", err)
	}
}

// A capacity below the build's ceiling is still a disagreement: the applet
// allocates its whole catalog from the installed R, so a smaller desired claim
// silently under-uses a card the operator believes is exactly full.
func TestVerifyDesiredCapacityRefusesAnUnderClaimWithinTheCeiling(t *testing.T) {
	spec := pinnedReleaseArtifact(t, t.TempDir(), 16, 64)
	if err := VerifyDesiredCapacity(spec, 8); err == nil {
		t.Fatal("VerifyDesiredCapacity accepted an under-claimed capacity")
	}
}

func TestLoadPinnedToolchainManifestRequiresCapacityProvenance(t *testing.T) {
	directory := t.TempDir()
	spec := pinnedReleaseArtifact(t, directory, 16, 64)
	// A manifest predating the capacity binding carries no capacity at all.
	legacy := map[string]string{
		"artifact_sha256": spec.SHA256, "source_ref": "working-tree", "source_commit": "10b8f42",
		"source_diff_sha256": stringsOf('d', 64), "java_version": "11", "javacard_kit": "jc304_kit",
		"ant_javacard_sha256": stringsOf('a', 64),
		"package_aid":         spec.PackageAID, "applet_aid": spec.AppletAID,
	}
	encoded, _ := json.Marshal(legacy)
	if err := os.WriteFile(spec.ToolchainManifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinnedToolchainManifest(spec); err == nil {
		t.Fatal("LoadPinnedToolchainManifest accepted a manifest without a capacity claim")
	}
}

func TestLoadPinnedToolchainManifestRefusesCapacityAboveTheCeiling(t *testing.T) {
	spec := pinnedReleaseArtifact(t, t.TempDir(), 128, 64)
	if _, err := LoadPinnedToolchainManifest(spec); err == nil {
		t.Fatal("LoadPinnedToolchainManifest accepted a capacity above the compiled ceiling")
	}
}

func TestPlanMigrationForDesiredBindsCapacityToThePinnedRelease(t *testing.T) {
	config, _ := migrationConfigWithPinnedRelease(t, 16, 64)
	if _, err := PlanMigrationForDesired(config, 16); err != nil {
		t.Fatalf("PlanMigrationForDesired: %v", err)
	}
	if _, err := PlanMigrationForDesired(config, 32); err == nil {
		t.Fatal("PlanMigrationForDesired planned a migration for a disagreeing capacity")
	}
}

// The whole point of the binding is that it fires before the card is touched.
func TestMigrationDryRunRefusesCapacityMismatchWithoutRunningAnyStage(t *testing.T) {
	config, _ := migrationConfigWithPinnedRelease(t, 16, 64)
	operations := &recordingMigrationOps{}
	executor := MigrationExecutor{Operations: operations, DesiredCapacity: 32}

	if _, err := executor.Execute(context.Background(), config, false, ""); err == nil {
		t.Fatal("dry-run accepted a capacity the pinned release CAP was not built with")
	}
	if _, err := executor.Execute(context.Background(), config, true, MaintenanceAcknowledgement(config)); err == nil {
		t.Fatal("execution accepted a capacity the pinned release CAP was not built with")
	}
	if len(operations.calls) != 0 {
		t.Fatalf("stages ran despite a refused capacity: %v", operations.calls)
	}

	executor.DesiredCapacity = 16
	result, err := executor.Execute(context.Background(), config, false, "")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Executed || len(result.Plan.Forward) == 0 {
		t.Fatalf("matching dry-run result = %+v", result)
	}
	if len(operations.calls) != 0 {
		t.Fatalf("dry-run ran stages: %v", operations.calls)
	}
}

// migrationConfigWithPinnedRelease returns a valid config whose release artifact
// really exists on disk with a matching digest and toolchain manifest.
func migrationConfigWithPinnedRelease(t *testing.T, capacity, maxCapacity int) (MigrationConfig, ArtifactSpec) {
	t.Helper()
	directory := t.TempDir()
	release := pinnedReleaseArtifact(t, directory, capacity, maxCapacity)
	config := validMigrationConfig()
	config.Release = release
	config.CanaryEvidencePath = filepath.Join(directory, "canary-evidence.json")
	config.ExportPath = filepath.Join(directory, "export.json")
	return config, release
}

func pinnedReleaseArtifact(t *testing.T, directory string, capacity, maxCapacity int) ArtifactSpec {
	t.Helper()
	artifactPath := filepath.Join(directory, "multi-rule.cap")
	artifact := []byte("multi-rule cap fixture")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	manifestPath := filepath.Join(directory, "release-toolchain.json")
	manifest := ToolchainManifest{
		ArtifactSHA256:        digestHex,
		SourceRef:             "working-tree",
		SourceCommit:          "10b8f42",
		SourceDiffSHA256:      stringsOf('d', 64),
		JavaVersion:           "11",
		JavaCardKit:           "jc304_kit",
		AntJavaCardSHA256:     stringsOf('a', 64),
		PackageAID:            StandardPackageAIDHex,
		AppletAID:             StandardInstanceAIDHex,
		ActiveRuleCapacity:    capacity,
		MaxActiveRuleCapacity: maxCapacity,
	}
	encoded, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	signaturePath := artifactPath + ".sig"
	publicKeyPath := filepath.Join(directory, "release-signing.pub")
	for _, path := range []string{signaturePath, publicKeyPath} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ArtifactSpec{
		Path: artifactPath, SHA256: digestHex,
		PackageAID: StandardPackageAIDHex, AppletAID: StandardInstanceAIDHex,
		SignaturePath: signaturePath, PublicKeyPath: publicKeyPath,
		ToolchainManifestPath: manifestPath,
	}
}
