package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type PackageManager interface {
	Delete(context.Context, string) error
	Install(context.Context, string, string, string, string) error
}

type GPHelperPackageManager struct {
	Runner      CommandRunner
	Binary      string
	Credentials SDCredentials
}

func (m GPHelperPackageManager) Delete(ctx context.Context, aid string) error {
	if err := m.validate(); err != nil {
		return err
	}
	if _, err := decodeAID(aid); err != nil {
		return fmt.Errorf("delete AID: %w", err)
	}
	_, err := m.Runner.Run(
		ctx,
		m.Binary,
		"delete-if-present",
		aid,
		m.Credentials.KIC,
		m.Credentials.KID,
		m.Credentials.KIK,
		m.Credentials.KeyVersion,
		m.Credentials.SCP,
		m.Credentials.I,
	)
	if err != nil {
		return errors.New("gp-t0-helper authenticated delete-if-present failed")
	}
	return nil
}

func (m GPHelperPackageManager) Install(ctx context.Context, capPath, packageAID, appletAID, instanceAID string) error {
	if err := m.validate(); err != nil {
		return err
	}
	for name, aid := range map[string]string{"package": packageAID, "applet": appletAID, "instance": instanceAID} {
		if _, err := decodeAID(aid); err != nil {
			return fmt.Errorf("%s AID: %w", name, err)
		}
	}
	if capPath == "" {
		return errors.New("CAP path is required")
	}
	if _, err := m.Runner.Run(
		ctx,
		m.Binary,
		"install",
		capPath,
		packageAID,
		appletAID,
		instanceAID,
		m.Credentials.KIC,
		m.Credentials.KID,
		m.Credentials.KIK,
		m.Credentials.KeyVersion,
		m.Credentials.SCP,
		m.Credentials.I,
	); err != nil {
		return errors.New("gp-t0-helper authenticated install failed")
	}
	return nil
}

func (m GPHelperPackageManager) validate() error {
	if m.Runner == nil || m.Binary == "" {
		return errors.New("gp-t0-helper runner and binary are required")
	}
	return m.Credentials.Validate()
}

type ArtifactVerifier interface {
	Verify(context.Context, ArtifactSpec) error
}

type LocalArtifactVerifier struct {
	Runner        CommandRunner
	OpenSSLBinary string
}

type ToolchainManifest struct {
	ArtifactSHA256    string `json:"artifact_sha256"`
	SourceRef         string `json:"source_ref"`
	SourceCommit      string `json:"source_commit"`
	SourceDiffSHA256  string `json:"source_diff_sha256"`
	JavaVersion       string `json:"java_version"`
	JavaCardKit       string `json:"javacard_kit"`
	AntJavaCardSHA256 string `json:"ant_javacard_sha256"`
	PackageAID        string `json:"package_aid"`
	AppletAID         string `json:"applet_aid"`
	// ActiveRuleCapacity is the active-rule capacity R this build runs with when
	// installed the way the provisioner installs it, that is with no capacity TLV
	// in the installation parameters. MaxActiveRuleCapacity is the build's
	// compiled ceiling for R.
	ActiveRuleCapacity    int `json:"active_rule_capacity"`
	MaxActiveRuleCapacity int `json:"max_active_rule_capacity"`
}

// LoadPinnedToolchainManifest binds a toolchain manifest to the artifact bytes it
// claims to describe: the CAP must hash to the pinned digest and the manifest must
// name that same digest, so neither file can be swapped on its own.
func LoadPinnedToolchainManifest(spec ArtifactSpec) (ToolchainManifest, error) {
	if err := validateArtifactSpec(spec); err != nil {
		return ToolchainManifest{}, err
	}
	artifact, err := readRegularFile(spec.Path, 32<<20)
	if err != nil {
		return ToolchainManifest{}, err
	}
	digest := sha256.Sum256(artifact)
	actualDigest := hex.EncodeToString(digest[:])
	if !strings.EqualFold(actualDigest, spec.SHA256) {
		return ToolchainManifest{}, errors.New("artifact SHA-256 does not match the pinned digest")
	}
	manifestBytes, err := readRegularFile(spec.ToolchainManifestPath, 1<<20)
	if err != nil {
		return ToolchainManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest ToolchainManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ToolchainManifest{}, fmt.Errorf("decode toolchain manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ToolchainManifest{}, err
	}
	if !strings.EqualFold(manifest.ArtifactSHA256, actualDigest) ||
		manifest.SourceRef == "" ||
		manifest.SourceCommit == "" ||
		!isSHA256(manifest.SourceDiffSHA256) ||
		manifest.JavaVersion == "" ||
		manifest.JavaCardKit == "" ||
		!isSHA256(manifest.AntJavaCardSHA256) ||
		!strings.EqualFold(manifest.PackageAID, spec.PackageAID) ||
		!strings.EqualFold(manifest.AppletAID, spec.AppletAID) ||
		manifest.ActiveRuleCapacity < 1 ||
		manifest.MaxActiveRuleCapacity < manifest.ActiveRuleCapacity {
		return ToolchainManifest{}, errors.New("toolchain manifest is incomplete or refers to a different artifact")
	}
	return manifest, nil
}

// VerifyDesiredCapacity refuses a desired-state capacity the pinned artifact
// cannot honour. Without it the disagreement only surfaces as a mid-rollout 6A84,
// after mutations have already been applied.
func VerifyDesiredCapacity(spec ArtifactSpec, desiredCapacity int) error {
	manifest, err := LoadPinnedToolchainManifest(spec)
	if err != nil {
		return fmt.Errorf("pinned artifact %s: %w", spec.Path, err)
	}
	if desiredCapacity != manifest.ActiveRuleCapacity {
		return fmt.Errorf(
			"desired manifest capacity %d disagrees with the pinned artifact %s, which was built with active-rule capacity %d",
			desiredCapacity, spec.Path, manifest.ActiveRuleCapacity)
	}
	return nil
}

func (v LocalArtifactVerifier) Verify(ctx context.Context, spec ArtifactSpec) error {
	if _, err := LoadPinnedToolchainManifest(spec); err != nil {
		return err
	}
	if _, err := readRegularFile(spec.SignaturePath, 1<<20); err != nil {
		return err
	}
	if _, err := readRegularFile(spec.PublicKeyPath, 1<<20); err != nil {
		return err
	}
	if v.Runner == nil || v.OpenSSLBinary == "" {
		return errors.New("OpenSSL runner and binary are required for detached-signature verification")
	}
	if _, err := v.Runner.Run(
		ctx,
		v.OpenSSLBinary,
		"dgst",
		"-sha256",
		"-verify",
		spec.PublicKeyPath,
		"-signature",
		spec.SignaturePath,
		spec.Path,
	); err != nil {
		return errors.New("artifact detached-signature verification failed")
	}
	return nil
}

type CanaryEvidence struct {
	CanarySHA256 string               `json:"canary_sha256"`
	Capacity     int                  `json:"capacity"`
	Checks       CanaryEvidenceChecks `json:"checks"`
}

type CanaryEvidenceChecks struct {
	RollbackInstallRestore bool `json:"rollback_install_restore"`
	CanaryInstall          bool `json:"canary_install"`
	Add                    bool `json:"add"`
	Overwrite              bool `json:"overwrite"`
	Delete                 bool `json:"delete"`
	FF40FF60               bool `json:"ff40_ff60"`
	RefreshChanges         bool `json:"refresh_changes"`
	InterruptionRecovery   bool `json:"interruption_recovery"`
	OwnedTransaction       bool `json:"owned_transaction"`
	CallerOwnedTransaction bool `json:"caller_owned_transaction"`
	RawStoreDenied         bool `json:"raw_store_denied"`
}

func VerifyCanaryEvidence(path string, canary ArtifactSpec, capacity int) error {
	contents, err := readRegularFile(path, 1<<20)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var evidence CanaryEvidence
	if err := decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("decode canary evidence: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	checks := evidence.Checks
	allChecks := checks.RollbackInstallRestore &&
		checks.CanaryInstall &&
		checks.Add &&
		checks.Overwrite &&
		checks.Delete &&
		checks.FF40FF60 &&
		checks.RefreshChanges &&
		checks.InterruptionRecovery &&
		checks.OwnedTransaction &&
		checks.CallerOwnedTransaction &&
		checks.RawStoreDenied
	if !strings.EqualFold(evidence.CanarySHA256, canary.SHA256) || evidence.Capacity != capacity || !allChecks {
		return errors.New("canary evidence does not prove every mandatory gate for the pinned artifact and capacity")
	}
	return nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, limit)
	}
	return contents, nil
}

type HostMigrationOperations struct {
	Reader          CatalogSource
	Sink            MutationSink
	Packages        PackageManager
	Artifacts       ArtifactVerifier
	Desired         []Rule
	Capacity        int
	InstanceAID     []byte
	Exported        []Rule
	VerifyRawDenied func(context.Context, Rule) error
	// AllowCatchAll opts the migration's desired-state reconciliation and
	// verification into the same host catch-all-grant policy that plan/reconcile
	// honour. Without it a legitimate catch-all grant in the desired manifest
	// fails closed on the migrate path.
	AllowCatchAll bool
}

func (o *HostMigrationOperations) planOptions() []PlanOption {
	if !o.AllowCatchAll {
		return nil
	}
	return []PlanOption{AllowCatchAllGrants()}
}

func (o *HostMigrationOperations) RunStage(ctx context.Context, stage MigrationStage, config MigrationConfig) error {
	switch stage {
	case MigrationExportCurrent:
		if o.Reader == nil || config.ExportPath == "" {
			return errors.New("catalog reader and secure export path are required")
		}
		snapshot, err := o.Reader.ReadCatalog(ctx)
		if err != nil {
			return err
		}
		if len(snapshot.Rules) != 1 {
			return fmt.Errorf("v0.1.1 migration requires exactly one exported rule, got %d", len(snapshot.Rules))
		}
		o.Exported = append([]Rule(nil), snapshot.Rules...)
		return SaveManifest(config.ExportPath, o.Exported, o.Capacity)
	case MigrationVerifyRollbackArtifact:
		return o.verifyArtifact(ctx, config.Rollback)
	case MigrationVerifyCanaryEvidence:
		if err := o.verifyArtifact(ctx, config.Canary); err != nil {
			return err
		}
		return VerifyCanaryEvidence(config.CanaryEvidencePath, config.Canary, o.Capacity)
	case MigrationVerifyReleaseArtifact:
		return o.verifyArtifact(ctx, config.Release)
	case MigrationGuardMaintenance:
		return nil
	case MigrationDeleteStandard:
		return o.deletePackage(ctx, config.StandardPackageAID)
	case MigrationInstallRelease:
		return o.installStandard(ctx, config.Release.Path, config)
	case MigrationRestoreExportedFirst:
		exported, err := o.exportedRules(config)
		if err != nil {
			return err
		}
		return o.reconcile(ctx, exported, true)
	case MigrationReconcileDesired:
		return o.reconcile(ctx, o.Desired, true)
	case MigrationVerifyRelease:
		return o.verifyCatalogAndRawStore(ctx, o.Desired)
	case MigrationDeletePartial:
		return o.deletePackage(ctx, config.StandardPackageAID)
	case MigrationInstallRollback:
		return o.installStandard(ctx, config.Rollback.Path, config)
	case MigrationRestoreExportedRollback:
		exported, err := o.exportedRules(config)
		if err != nil {
			return err
		}
		return o.reconcile(ctx, exported, true)
	case MigrationVerifyRollback:
		exported, err := o.exportedRules(config)
		if err != nil {
			return err
		}
		return o.verifyCatalogAndRawStore(ctx, exported)
	default:
		return fmt.Errorf("unsupported migration stage %q", stage)
	}
}

func (o *HostMigrationOperations) verifyArtifact(ctx context.Context, artifact ArtifactSpec) error {
	if o.Artifacts == nil {
		return errors.New("artifact verifier is required")
	}
	return o.Artifacts.Verify(ctx, artifact)
}

func (o *HostMigrationOperations) deletePackage(ctx context.Context, aid string) error {
	if o.Packages == nil {
		return errors.New("authenticated package manager is required")
	}
	return o.Packages.Delete(ctx, aid)
}

func (o *HostMigrationOperations) installStandard(ctx context.Context, capPath string, config MigrationConfig) error {
	if o.Packages == nil {
		return errors.New("authenticated package manager is required")
	}
	return o.Packages.Install(ctx, capPath, config.StandardPackageAID, config.StandardInstanceAID, config.StandardInstanceAID)
}

func (o *HostMigrationOperations) reconcile(ctx context.Context, desired []Rule, execute bool) error {
	reconciler := Reconciler{Source: o.Reader, Sink: o.Sink}
	result, err := reconciler.Reconcile(ctx, desired, o.Capacity, execute, o.planOptions()...)
	if err != nil {
		return err
	}
	if execute && !result.Verified {
		return errors.New("catalog reconciliation did not verify")
	}
	return nil
}

func (o *HostMigrationOperations) verifyCatalogAndRawStore(ctx context.Context, desired []Rule) error {
	if o.Reader == nil {
		return errors.New("catalog reader is required")
	}
	snapshot, err := o.Reader.ReadCatalog(ctx)
	if err != nil {
		return err
	}
	remaining, err := PlanDiff(snapshot.Rules, desired, o.Capacity, o.planOptions()...)
	if err != nil {
		return err
	}
	if len(remaining.Mutations) != 0 {
		return fmt.Errorf("verification found %d desired/current differences", len(remaining.Mutations))
	}
	if len(desired) == 0 || o.VerifyRawDenied == nil {
		return errors.New("a known idempotent rule and raw-STORE denial verifier are required")
	}
	return o.VerifyRawDenied(ctx, desired[0])
}

func (o *HostMigrationOperations) exportedRules(config MigrationConfig) ([]Rule, error) {
	if len(o.Exported) != 0 {
		return o.Exported, nil
	}
	rules, _, err := LoadManifest(config.ExportPath)
	if err != nil {
		return nil, fmt.Errorf("load secure exported-rule manifest: %w", err)
	}
	o.Exported = rules
	return o.Exported, nil
}

func (r JCHarnessReader) VerifyRawStoreDenied(ctx context.Context, idempotentRule Rule) error {
	if r.Runner == nil || r.Binary == "" || r.Reader == "" || len(r.InstanceAID) < 5 || len(r.InstanceAID) > 16 {
		return errors.New("valid jc-harness runner, binary, reader, and ARA-M instance AID are required")
	}
	mutation, err := newUpsertMutation(PhaseUpdate, idempotentRule)
	if err != nil {
		return err
	}
	selectAPDU := []byte{0x00, 0xA4, 0x04, 0x00, byte(len(r.InstanceAID))}
	selectAPDU = append(selectAPDU, r.InstanceAID...)
	apdus := strings.Join([]string{hexUpperBytes(selectAPDU), hexUpperBytes(mutation.APDU)}, ",")
	output, err := r.Runner.Run(ctx, r.Binary, "seq", "--reader", r.Reader, "--apdu", apdus)
	if err != nil {
		return errors.New("jc-harness raw-STORE denial sequence failed")
	}
	var sequence jcHarnessSequence
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sequence); err != nil {
		return fmt.Errorf("decode raw-STORE denial response: %w", err)
	}
	if len(sequence.Results) != 2 || normalizeSW(sequence.Results[0].SW) != "9000" || normalizeSW(sequence.Results[1].SW) != "6982" {
		return errors.New("raw selected-applet STORE DATA was not rejected with 6982")
	}
	return nil
}
