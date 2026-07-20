package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactVerifierChecksDigestManifestAndSignature(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "release.cap")
	artifact := []byte("cap fixture")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	manifestPath := filepath.Join(directory, "toolchain.json")
	manifest := ToolchainManifest{
		ArtifactSHA256:        digestHex,
		SourceRef:             "v0.1.1",
		SourceCommit:          "10b8f42",
		SourceDiffSHA256:      stringsOf('d', 64),
		JavaVersion:           "11",
		JavaCardKit:           "jc304_kit",
		AntJavaCardSHA256:     stringsOf('a', 64),
		PackageAID:            StandardPackageAIDHex,
		AppletAID:             StandardInstanceAIDHex,
		ActiveRuleCapacity:    16,
		MaxActiveRuleCapacity: 64,
	}
	manifestJSON, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(directory, "release.cap.sig")
	publicKeyPath := filepath.Join(directory, "release.pub")
	for _, path := range []string{signaturePath, publicKeyPath} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingRunner{}
	verifier := LocalArtifactVerifier{Runner: runner, OpenSSLBinary: "openssl"}
	spec := ArtifactSpec{Path: artifactPath, SHA256: digestHex, PackageAID: StandardPackageAIDHex, AppletAID: StandardInstanceAIDHex, SignaturePath: signaturePath, PublicKeyPath: publicKeyPath, ToolchainManifestPath: manifestPath}
	if err := verifier.Verify(context.Background(), spec); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if runner.name != "openssl" || !containsArg(runner.args, "-verify") {
		t.Fatalf("signature verification invocation = %s %v", runner.name, runner.args)
	}

	spec.SHA256 = stringsOf('b', 64)
	if err := verifier.Verify(context.Background(), spec); err == nil {
		t.Fatal("Verify unexpectedly accepted a mismatched digest")
	}

	manifest.SourceDiffSHA256 = ""
	manifestJSON, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	spec.SHA256 = digestHex
	if err := verifier.Verify(context.Background(), spec); err == nil {
		t.Fatal("Verify unexpectedly accepted a manifest without source diff provenance")
	}

	manifest.SourceDiffSHA256 = stringsOf('d', 64)
	manifest.AppletAID = "A00000015141434D00"
	manifestJSON, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), spec); err == nil {
		t.Fatal("Verify unexpectedly accepted a manifest for a different applet AID")
	}
}

func TestGPHelperPackageManagerUsesFailClosedDeleteIfPresent(t *testing.T) {
	runner := &recordingRunner{output: []byte("Already absent A00000015141434C (SW=6A88)\n")}
	manager := GPHelperPackageManager{
		Runner: runner,
		Binary: "gp-t0-helper",
		Credentials: SDCredentials{
			KIC:        "00112233445566778899AABBCCDDEEFF",
			KID:        "00112233445566778899AABBCCDDEEFF",
			KIK:        "00112233445566778899AABBCCDDEEFF",
			KeyVersion: "20",
			SCP:        "SCP02",
			I:          "15",
		},
	}
	if err := manager.Delete(context.Background(), StandardPackageAIDHex); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(runner.args) == 0 || runner.args[0] != "delete-if-present" {
		t.Fatalf("delete command = %v", runner.args)
	}
}

func TestGPHelperPackageManagerInstallUsesAuthenticatedHelper(t *testing.T) {
	runner := &recordingRunner{}
	manager := GPHelperPackageManager{Runner: runner, Binary: "gp-t0-helper", Credentials: validTestCredentials()}
	if err := manager.Install(context.Background(), "release.cap", StandardPackageAIDHex, StandardInstanceAIDHex, StandardInstanceAIDHex); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(runner.args) == 0 || runner.args[0] != "install" {
		t.Fatalf("install command = %v", runner.args)
	}
}

func TestLoadMigrationConfigResolvesRelativeArtifactPaths(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "migration.json")
	config := validMigrationConfig()
	config.ExportPath = "export.json"
	encoded, _ := json.Marshal(config)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMigrationConfig(path)
	if err != nil {
		t.Fatalf("LoadMigrationConfig: %v", err)
	}
	if loaded.Release.Path != filepath.Join(directory, "multi-rule.cap") || loaded.ExportPath != filepath.Join(directory, "export.json") {
		t.Fatalf("relative paths were not resolved: %+v", loaded)
	}
}

func TestVerifyCanaryEvidenceRequiresEveryGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canary.json")
	evidence := CanaryEvidence{
		CanarySHA256: stringsOf('c', 64),
		Capacity:     16,
		Checks: CanaryEvidenceChecks{
			RollbackInstallRestore: true,
			CanaryInstall:          true,
			Add:                    true,
			Overwrite:              true,
			Delete:                 true,
			FF40FF60:               true,
			RefreshChanges:         true,
			InterruptionRecovery:   true,
			OwnedTransaction:       true,
			CallerOwnedTransaction: true,
			RawStoreDenied:         true,
		},
	}
	encoded, _ := json.Marshal(evidence)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanaryEvidence(path, validMigrationConfig().Canary, 16); err != nil {
		t.Fatalf("VerifyCanaryEvidence: %v", err)
	}
	evidence.Checks.RawStoreDenied = false
	encoded, _ = json.Marshal(evidence)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanaryEvidence(path, validMigrationConfig().Canary, 16); err == nil {
		t.Fatal("VerifyCanaryEvidence accepted an incomplete gate set")
	}
}

func TestHostMigrationOperationsRunForwardAndRollbackStages(t *testing.T) {
	exported := testRule(t, "F0000000AA01", "", 0x01)
	additional := testRule(t, "F0000000BB01", "", 0x01)
	state := newMemoryCatalog(exported)
	sink := &interruptingMutator{state: state, failAfter: -1}
	packages := &memoryPackageManager{state: state}
	artifacts := &acceptingArtifactVerifier{}
	directory := t.TempDir()
	evidencePath := filepath.Join(directory, "canary.json")
	evidence := CanaryEvidence{CanarySHA256: stringsOf('c', 64), Capacity: 16, Checks: CanaryEvidenceChecks{
		RollbackInstallRestore: true, CanaryInstall: true, Add: true, Overwrite: true,
		Delete: true, FF40FF60: true, RefreshChanges: true, InterruptionRecovery: true,
		OwnedTransaction: true, CallerOwnedTransaction: true, RawStoreDenied: true,
	}}
	evidenceJSON, _ := json.Marshal(evidence)
	if err := os.WriteFile(evidencePath, evidenceJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	config := validMigrationConfig()
	config.CanaryEvidencePath = evidencePath
	config.ExportPath = filepath.Join(directory, "export.json")
	rawChecks := 0
	operations := &HostMigrationOperations{
		Reader: state, Sink: sink, Packages: packages, Artifacts: artifacts,
		Desired: []Rule{exported, additional}, Capacity: 16,
		VerifyRawDenied: func(context.Context, Rule) error { rawChecks++; return nil },
	}
	plan, err := PlanMigration(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range plan.Forward {
		if err := operations.RunStage(context.Background(), stage, config); err != nil {
			t.Fatalf("forward stage %s: %v", stage, err)
		}
	}
	for _, stage := range plan.Rollback {
		if err := operations.RunStage(context.Background(), stage, config); err != nil {
			t.Fatalf("rollback stage %s: %v", stage, err)
		}
	}
	if rawChecks != 2 || artifacts.calls != 3 {
		t.Fatalf("raw checks=%d artifact checks=%d", rawChecks, artifacts.calls)
	}
	if len(state.rules) != 1 {
		t.Fatalf("rollback catalog size = %d, want 1", len(state.rules))
	}
}

func TestHostMigrationOperationsCatchAllGrantHonoursAllowFlag(t *testing.T) {
	catchAllGrant := testRule(t, "", "", 0x01)

	// Fail-closed without the flag: the reconcile stage refuses the catch-all
	// grant and never touches the sink, matching plan/reconcile.
	closedState := newMemoryCatalog()
	closedSink := &interruptingMutator{state: closedState, failAfter: -1}
	closed := &HostMigrationOperations{
		Reader: closedState, Sink: closedSink,
		Desired: []Rule{catchAllGrant}, Capacity: 16,
		VerifyRawDenied: func(context.Context, Rule) error { return nil },
	}
	if err := closed.RunStage(context.Background(), MigrationReconcileDesired, validMigrationConfig()); err == nil {
		t.Fatal("migrate reconcile accepted a catch-all grant without --allow-catch-all")
	}
	if closedSink.calls != 0 {
		t.Fatalf("sink calls = %d, want 0 when the catch-all grant is refused", closedSink.calls)
	}

	// With the flag the same catch-all grant reconciles and verifies cleanly.
	openState := newMemoryCatalog()
	openSink := &interruptingMutator{state: openState, failAfter: -1}
	rawChecks := 0
	open := &HostMigrationOperations{
		Reader: openState, Sink: openSink,
		Desired: []Rule{catchAllGrant}, Capacity: 16,
		VerifyRawDenied: func(context.Context, Rule) error { rawChecks++; return nil },
		AllowCatchAll:   true,
	}
	if err := open.RunStage(context.Background(), MigrationReconcileDesired, validMigrationConfig()); err != nil {
		t.Fatalf("migrate reconcile with --allow-catch-all: %v", err)
	}
	if openSink.calls != 1 {
		t.Fatalf("sink calls = %d, want 1 after the catch-all grant reconciles", openSink.calls)
	}
	if err := open.RunStage(context.Background(), MigrationVerifyRelease, validMigrationConfig()); err != nil {
		t.Fatalf("migrate verify with --allow-catch-all: %v", err)
	}
	if rawChecks != 1 {
		t.Fatalf("raw-store checks = %d, want 1", rawChecks)
	}
}

func TestJCHarnessRawStoreDenialVerification(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"reader": "test", "results": []map[string]string{{"sw": "9000", "data": ""}, {"sw": "6982", "data": ""}}})
	runner := &recordingRunner{output: payload}
	reader := JCHarnessReader{Runner: runner, Binary: "jc-harness", Reader: "OMNIKEY", InstanceAID: mustHex(t, StandardInstanceAIDHex), Capacity: 16}
	if err := reader.VerifyRawStoreDenied(context.Background(), testRule(t, "F0000000AA01", "", 0x01)); err != nil {
		t.Fatalf("VerifyRawStoreDenied: %v", err)
	}
}

func validTestCredentials() SDCredentials {
	return SDCredentials{
		KIC:        "00112233445566778899AABBCCDDEEFF",
		KID:        "00112233445566778899AABBCCDDEEFF",
		KIK:        "00112233445566778899AABBCCDDEEFF",
		KeyVersion: "20", SCP: "SCP02", I: "15",
	}
}

type acceptingArtifactVerifier struct{ calls int }

func (v *acceptingArtifactVerifier) Verify(context.Context, ArtifactSpec) error {
	v.calls++
	return nil
}

type memoryPackageManager struct{ state *memoryCatalog }

func (m *memoryPackageManager) Delete(context.Context, string) error {
	m.state.rules = make(map[string]Rule)
	return nil
}

func (m *memoryPackageManager) Install(context.Context, string, string, string, string) error {
	return nil
}
