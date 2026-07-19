package provisioner

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

const defaultRecoveryTimeout = 5 * time.Minute

type ArtifactSpec struct {
	Path                  string `json:"path"`
	SHA256                string `json:"sha256"`
	PackageAID            string `json:"package_aid"`
	AppletAID             string `json:"applet_aid"`
	SignaturePath         string `json:"signature_path"`
	PublicKeyPath         string `json:"public_key_path"`
	ToolchainManifestPath string `json:"toolchain_manifest_path"`
}

type MigrationConfig struct {
	StandardPackageAID  string       `json:"standard_package_aid"`
	StandardInstanceAID string       `json:"standard_instance_aid"`
	CanaryPackageAID    string       `json:"canary_package_aid"`
	CanaryInstanceAID   string       `json:"canary_instance_aid"`
	Rollback            ArtifactSpec `json:"rollback"`
	Canary              ArtifactSpec `json:"canary"`
	Release             ArtifactSpec `json:"release"`
	CanaryEvidencePath  string       `json:"canary_evidence_path"`
	ExportPath          string       `json:"export_path"`
}

type MigrationStage string

const (
	MigrationExportCurrent           MigrationStage = "export-current-rule"
	MigrationVerifyRollbackArtifact  MigrationStage = "verify-rollback-artifact"
	MigrationVerifyCanaryEvidence    MigrationStage = "verify-canary-artifact-and-evidence"
	MigrationVerifyReleaseArtifact   MigrationStage = "verify-release-artifact"
	MigrationGuardMaintenance        MigrationStage = "guard-standard-aid-maintenance"
	MigrationDeleteStandard          MigrationStage = "delete-v0.1.1-standard-package"
	MigrationInstallRelease          MigrationStage = "install-multi-rule-standard-package"
	MigrationRestoreExportedFirst    MigrationStage = "restore-exported-rule-first"
	MigrationReconcileDesired        MigrationStage = "reconcile-full-desired-catalog"
	MigrationVerifyRelease           MigrationStage = "verify-release-catalog-refresh-and-raw-store-denial"
	MigrationDeletePartial           MigrationStage = "rollback-delete-partial-multi-rule"
	MigrationInstallRollback         MigrationStage = "rollback-install-v0.1.1-standard-package"
	MigrationRestoreExportedRollback MigrationStage = "rollback-restore-exported-rule"
	MigrationVerifyRollback          MigrationStage = "rollback-verify-catalog-refresh-and-raw-store-denial"
)

type MigrationPlan struct {
	Forward  []MigrationStage `json:"forward"`
	Rollback []MigrationStage `json:"rollback_on_failure"`
}

func PlanMigration(config MigrationConfig) (MigrationPlan, error) {
	if err := validateMigrationConfig(config); err != nil {
		return MigrationPlan{}, err
	}
	return MigrationPlan{
		Forward: []MigrationStage{
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
		},
		Rollback: []MigrationStage{
			MigrationDeletePartial,
			MigrationInstallRollback,
			MigrationRestoreExportedRollback,
			MigrationVerifyRollback,
		},
	}, nil
}

// PlanMigrationForDesired plans the migration for a concrete desired-state
// capacity. The capacity claim is cross-checked against the pinned release CAP
// before any stage is returned, so a manifest that disagrees with the artifact it
// will run on is refused on the planning path, dry-run included.
func PlanMigrationForDesired(config MigrationConfig, desiredCapacity int) (MigrationPlan, error) {
	plan, err := PlanMigration(config)
	if err != nil {
		return MigrationPlan{}, err
	}
	if err := VerifyDesiredCapacity(config.Release, desiredCapacity); err != nil {
		return MigrationPlan{}, err
	}
	return plan, nil
}

func LoadMigrationConfig(path string) (MigrationConfig, error) {
	file, err := openSecureInput(path)
	if err != nil {
		return MigrationConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config MigrationConfig
	if err := decoder.Decode(&config); err != nil {
		return MigrationConfig{}, fmt.Errorf("decode migration config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return MigrationConfig{}, err
	}
	base := filepath.Dir(path)
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Join(base, value)
	}
	for _, artifact := range []*ArtifactSpec{&config.Rollback, &config.Canary, &config.Release} {
		artifact.Path = resolve(artifact.Path)
		artifact.SignaturePath = resolve(artifact.SignaturePath)
		artifact.PublicKeyPath = resolve(artifact.PublicKeyPath)
		artifact.ToolchainManifestPath = resolve(artifact.ToolchainManifestPath)
	}
	config.CanaryEvidencePath = resolve(config.CanaryEvidencePath)
	config.ExportPath = resolve(config.ExportPath)
	if _, err := PlanMigration(config); err != nil {
		return MigrationConfig{}, err
	}
	return config, nil
}

func validateMigrationConfig(config MigrationConfig) error {
	if config.StandardPackageAID != StandardPackageAIDHex || config.StandardInstanceAID != StandardInstanceAIDHex {
		return errors.New("standard package/instance AIDs must match the accepted ARA-M identity")
	}
	canaryPackage, err := decodeAID(config.CanaryPackageAID)
	if err != nil {
		return fmt.Errorf("canary package AID: %w", err)
	}
	canaryInstance, err := decodeAID(config.CanaryInstanceAID)
	if err != nil {
		return fmt.Errorf("canary instance AID: %w", err)
	}
	if config.CanaryPackageAID == config.StandardPackageAID || config.CanaryInstanceAID == config.StandardInstanceAID {
		return errors.New("canary AIDs must differ from the standard ARA-M AIDs")
	}
	if len(canaryInstance) <= len(canaryPackage) || string(canaryInstance[:len(canaryPackage)]) != string(canaryPackage) {
		return errors.New("canary instance AID must extend the canary package AID")
	}
	for name, artifact := range map[string]ArtifactSpec{"rollback": config.Rollback, "canary": config.Canary, "release": config.Release} {
		if err := validateArtifactSpec(artifact); err != nil {
			return fmt.Errorf("%s artifact: %w", name, err)
		}
	}
	if config.Rollback.PackageAID != config.StandardPackageAID || config.Rollback.AppletAID != config.StandardInstanceAID ||
		config.Release.PackageAID != config.StandardPackageAID || config.Release.AppletAID != config.StandardInstanceAID {
		return errors.New("rollback and release artifacts must pin the standard package/instance AIDs")
	}
	if config.Canary.PackageAID != config.CanaryPackageAID || config.Canary.AppletAID != config.CanaryInstanceAID {
		return errors.New("canary artifact must pin the configured alternate package/instance AIDs")
	}
	if config.CanaryEvidencePath == "" {
		return errors.New("canary evidence path is required")
	}
	if config.ExportPath == "" {
		return errors.New("secure exported-rule path is required")
	}
	return nil
}

func validateArtifactSpec(spec ArtifactSpec) error {
	if spec.Path == "" || spec.PackageAID == "" || spec.AppletAID == "" || spec.SignaturePath == "" || spec.PublicKeyPath == "" || spec.ToolchainManifestPath == "" {
		return errors.New("path, package/applet AIDs, detached signature, public key, and toolchain manifest are required")
	}
	if !isSHA256(spec.SHA256) {
		return errors.New("sha256 must be exactly 32 hex bytes")
	}
	packageAID, err := decodeAID(spec.PackageAID)
	if err != nil {
		return fmt.Errorf("package AID: %w", err)
	}
	appletAID, err := decodeAID(spec.AppletAID)
	if err != nil {
		return fmt.Errorf("applet AID: %w", err)
	}
	if len(appletAID) <= len(packageAID) || string(appletAID[:len(packageAID)]) != string(packageAID) {
		return errors.New("applet AID must extend the package AID")
	}
	return nil
}

func isSHA256(encoded string) bool {
	digest, err := hex.DecodeString(encoded)
	return err == nil && len(digest) == 32
}

func decodeAID(encoded string) ([]byte, error) {
	aid, err := hex.DecodeString(encoded)
	if err != nil || len(aid) < 5 || len(aid) > 16 {
		return nil, errors.New("must be 5..16 bytes of hex")
	}
	return aid, nil
}

func MaintenanceAcknowledgement(config MigrationConfig) string {
	return "REPLACE_STANDARD_ARA_M_" + config.StandardInstanceAID
}

type MigrationOperations interface {
	RunStage(context.Context, MigrationStage, MigrationConfig) error
}

type MigrationExecutor struct {
	Operations      MigrationOperations
	RecoveryTimeout time.Duration
	// DesiredCapacity is the capacity declared by the desired-state manifest. It
	// is cross-checked against the pinned release CAP on the planning path.
	DesiredCapacity int
}

type MigrationResult struct {
	Plan       MigrationPlan `json:"plan"`
	Executed   bool          `json:"executed"`
	RolledBack bool          `json:"rolled_back"`
}

func (e MigrationExecutor) Execute(ctx context.Context, config MigrationConfig, execute bool, acknowledgement string) (MigrationResult, error) {
	plan, err := PlanMigrationForDesired(config, e.DesiredCapacity)
	if err != nil {
		return MigrationResult{}, err
	}
	result := MigrationResult{Plan: plan}
	if !execute {
		return result, nil
	}
	if e.Operations == nil {
		return result, errors.New("migration operations are required for execution")
	}
	if acknowledgement != MaintenanceAcknowledgement(config) {
		return result, errors.New("standard-AID replacement acknowledgement does not match the guarded maintenance token")
	}
	result.Executed = true
	destructiveStarted := false
	for _, stage := range plan.Forward {
		if stage == MigrationDeleteStandard {
			destructiveStarted = true
		}
		if err := e.Operations.RunStage(ctx, stage, config); err != nil {
			if !destructiveStarted {
				return result, fmt.Errorf("migration preflight stage %s failed: %w", stage, err)
			}
			rollbackErr := e.runRollback(plan.Rollback, config)
			result.RolledBack = rollbackErr == nil
			if rollbackErr != nil {
				return result, fmt.Errorf("migration stage %s failed (%v) and rollback failed: %w", stage, err, rollbackErr)
			}
			return result, fmt.Errorf("migration stage %s failed; v0.1.1 rollback path ran successfully: %w", stage, err)
		}
	}
	return result, nil
}

func (e MigrationExecutor) runRollback(stages []MigrationStage, config MigrationConfig) error {
	timeout := e.RecoveryTimeout
	if timeout <= 0 {
		timeout = defaultRecoveryTimeout
	}
	// Recovery is a card-safety boundary. It must remain runnable when the
	// forward operation's caller context is canceled or its deadline expires.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, stage := range stages {
		if err := e.Operations.RunStage(ctx, stage, config); err != nil {
			return fmt.Errorf("rollback stage %s: %w", stage, err)
		}
	}
	return nil
}
