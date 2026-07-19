package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	provisioner "github.com/relux-works/jc-ara-m/host"
)

const commandTimeout = 5 * time.Minute

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("missing command: plan, reconcile, migration-plan, or migrate"))
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = runPlan(os.Args[2:])
	case "reconcile":
		err = runReconcile(os.Args[2:])
	case "migration-plan":
		err = runMigrationPlan(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func runPlan(args []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	currentPath := flags.String("current", "", "0600 JSON manifest containing the current catalog")
	desiredPath := flags.String("desired", "", "0600 JSON manifest containing the desired catalog")
	allowCatchAll := flags.Bool("allow-catch-all", false, "opt in to a desired rule granting access to every SE applet")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *currentPath == "" || *desiredPath == "" {
		return errors.New("plan requires --current and --desired")
	}
	current, currentCapacity, err := provisioner.LoadManifest(*currentPath)
	if err != nil {
		return err
	}
	desired, desiredCapacity, err := provisioner.LoadManifest(*desiredPath)
	if err != nil {
		return err
	}
	if currentCapacity != desiredCapacity {
		return fmt.Errorf("manifest capacities differ: current=%d desired=%d", currentCapacity, desiredCapacity)
	}
	plan, err := provisioner.PlanDiff(current, desired, desiredCapacity, planOptions(*allowCatchAll)...)
	if err != nil {
		return err
	}
	return emit(map[string]any{"ok": true, "dry_run": true, "plan": plan.Summary()})
}

func runReconcile(args []string) error {
	flags := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	desiredPath := flags.String("desired", "", "0600 JSON desired-state manifest")
	readerName := flags.String("reader", "", "explicit jc-harness reader selector")
	instanceAIDHex := flags.String("instance-aid", provisioner.StandardInstanceAIDHex, "ARA-M instance AID")
	credentialsPath := flags.String("credentials", "", "0600 Security Domain credentials JSON")
	jcHarness := flags.String("jc-harness", "jc-harness", "jc-harness executable")
	gpHelper := flags.String("gp-t0-helper", "gp-t0-helper", "gp-t0-helper executable")
	execute := flags.Bool("execute", false, "apply the authenticated N-command manifest")
	allowCatchAll := flags.Bool("allow-catch-all", false, "opt in to a desired rule granting access to every SE applet")
	migrationConfig := flags.String("migration-config", "", "0600 migration config JSON binding the desired capacity to the pinned release CAP")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *desiredPath == "" || *readerName == "" {
		return errors.New("reconcile requires --desired and --reader")
	}
	desired, capacity, err := provisioner.LoadManifest(*desiredPath)
	if err != nil {
		return err
	}
	if *migrationConfig != "" {
		config, err := provisioner.LoadMigrationConfig(*migrationConfig)
		if err != nil {
			return err
		}
		if err := provisioner.VerifyDesiredCapacity(config.Release, capacity); err != nil {
			return err
		}
	}
	instanceAID, err := decodeAID(*instanceAIDHex)
	if err != nil {
		return err
	}
	runner := provisioner.ExecCommandRunner{}
	reader := provisioner.JCHarnessReader{
		Runner: runner, Binary: *jcHarness, Reader: *readerName,
		InstanceAID: instanceAID, Capacity: capacity,
	}
	var sink provisioner.MutationSink
	if *execute {
		if *credentialsPath == "" {
			return errors.New("--execute requires --credentials")
		}
		credentials, err := provisioner.LoadCredentials(*credentialsPath)
		if err != nil {
			return err
		}
		sink = provisioner.GPHelperSink{
			Runner: runner, Binary: *gpHelper, InstanceAID: instanceAID, Credentials: credentials,
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	result, err := (provisioner.Reconciler{Source: reader, Sink: sink}).Reconcile(
		ctx, desired, capacity, *execute, planOptions(*allowCatchAll)...)
	if err != nil {
		return err
	}
	return emit(map[string]any{
		"ok": true, "dry_run": !*execute, "executed": result.Executed,
		"verified": result.Verified, "plan": result.Plan.Summary(),
	})
}

func runMigrationPlan(args []string) error {
	flags := flag.NewFlagSet("migration-plan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "0600 migration config JSON")
	desiredPath := flags.String("desired", "", "0600 desired-state manifest whose capacity is bound to the pinned release CAP")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *desiredPath == "" {
		return errors.New("migration-plan requires --config and --desired")
	}
	config, err := provisioner.LoadMigrationConfig(*configPath)
	if err != nil {
		return err
	}
	_, capacity, err := provisioner.LoadManifest(*desiredPath)
	if err != nil {
		return err
	}
	plan, err := provisioner.PlanMigrationForDesired(config, capacity)
	if err != nil {
		return err
	}
	return emit(map[string]any{
		"ok": true, "dry_run": true, "plan": plan, "capacity": capacity,
		"required_acknowledgement": provisioner.MaintenanceAcknowledgement(config),
	})
}

func runMigrate(args []string) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "0600 migration config JSON")
	desiredPath := flags.String("desired", "", "0600 desired-state manifest restored after the exported original rule")
	credentialsPath := flags.String("credentials", "", "0600 Security Domain credentials JSON")
	readerName := flags.String("reader", "", "explicit jc-harness reader selector")
	jcHarness := flags.String("jc-harness", "jc-harness", "jc-harness executable")
	gpHelper := flags.String("gp-t0-helper", "gp-t0-helper", "gp-t0-helper executable")
	opensslBinary := flags.String("openssl", "openssl", "OpenSSL executable")
	execute := flags.Bool("execute", false, "perform guarded standard-AID replacement")
	acknowledgement := flags.String("ack", "", "exact maintenance acknowledgement printed by migration-plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *desiredPath == "" {
		return errors.New("migrate requires --config and --desired")
	}
	config, err := provisioner.LoadMigrationConfig(*configPath)
	if err != nil {
		return err
	}
	desired, capacity, err := provisioner.LoadManifest(*desiredPath)
	if err != nil {
		return err
	}
	if !*execute {
		result, err := (provisioner.MigrationExecutor{DesiredCapacity: capacity}).Execute(context.Background(), config, false, "")
		if err != nil {
			return err
		}
		return emit(map[string]any{
			"ok": true, "dry_run": true, "result": result, "capacity": capacity,
			"required_acknowledgement": provisioner.MaintenanceAcknowledgement(config),
		})
	}
	if *credentialsPath == "" || *readerName == "" {
		return errors.New("migrate --execute requires --credentials and --reader")
	}
	if config.ExportPath == "" {
		return errors.New("migrate --execute requires export_path in migration config")
	}
	credentials, err := provisioner.LoadCredentials(*credentialsPath)
	if err != nil {
		return err
	}
	instanceAID, err := decodeAID(config.StandardInstanceAID)
	if err != nil {
		return err
	}
	runner := provisioner.ExecCommandRunner{}
	reader := provisioner.JCHarnessReader{
		Runner: runner, Binary: *jcHarness, Reader: *readerName,
		InstanceAID: instanceAID, Capacity: capacity,
	}
	sink := provisioner.GPHelperSink{
		Runner: runner, Binary: *gpHelper, InstanceAID: instanceAID, Credentials: credentials,
	}
	operations := &provisioner.HostMigrationOperations{
		Reader:          reader,
		Sink:            sink,
		Packages:        provisioner.GPHelperPackageManager{Runner: runner, Binary: *gpHelper, Credentials: credentials},
		Artifacts:       provisioner.LocalArtifactVerifier{Runner: runner, OpenSSLBinary: *opensslBinary},
		Desired:         desired,
		Capacity:        capacity,
		InstanceAID:     instanceAID,
		VerifyRawDenied: reader.VerifyRawStoreDenied,
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	result, err := (provisioner.MigrationExecutor{
		Operations:      operations,
		RecoveryTimeout: commandTimeout,
		DesiredCapacity: capacity,
	}).Execute(ctx, config, true, *acknowledgement)
	if err != nil {
		return err
	}
	return emit(map[string]any{"ok": true, "dry_run": false, "result": result})
}

func planOptions(allowCatchAll bool) []provisioner.PlanOption {
	if !allowCatchAll {
		return nil
	}
	return []provisioner.PlanOption{provisioner.AllowCatchAllGrants()}
}

func decodeAID(encoded string) ([]byte, error) {
	aid, err := hex.DecodeString(encoded)
	if err != nil || len(aid) < 5 || len(aid) > 16 {
		return nil, errors.New("instance AID must be 5..16 bytes of hex")
	}
	return aid, nil
}

func emit(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func fail(err error) {
	_ = emit(map[string]any{"ok": false, "error": err.Error()})
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `aram-provisioner — authenticated desired-state ARA-M host controller

Commands:
  plan --current FILE --desired FILE [--allow-catch-all]
      Offline, no-card deterministic updates->deletes->adds plan. Output is
      sanitized: key/rule digests and lengths only, never rule bytes. A desired
      rule that grants access through the zero-length AID-REF-DO catch-all is
      refused unless --allow-catch-all is passed; a catch-all deny never needs it.

  reconcile --desired FILE --reader NAME [--execute --credentials FILE]
            [--allow-catch-all] [--migration-config FILE]
      Re-read FF40/FF60 via jc-harness, diff, and optionally send one
      authenticated gp-t0-helper secure-apdu manifest. Re-run after any
      transport interruption; the command always re-reads/re-diffs. With
      --migration-config the desired capacity is cross-checked against the
      pinned release CAP before anything is planned.

  migration-plan --config FILE --desired FILE
      Validate and print the guarded v0.1.1 export/reinstall/import plan plus
      its rollback branch. Performs no hardware command. The desired manifest's
      capacity must equal the capacity the pinned release CAP was built with.

  migrate --config FILE --desired FILE [--execute --ack TOKEN
          --credentials FILE --reader NAME]
      Without --execute, dry-run only. Both modes cross-check the desired
      capacity against the pinned release CAP, so a capacity disagreement is
      refused before any card mutation. Execution requires the exact printed
      maintenance token, pinned signed rollback/canary/release artifacts,
      complete canary evidence, and a secure exported-rule path.

All manifests, credentials, and migration config files must be regular,
non-symlink files with mode 0600 (or stricter). Physical mutation is never an
implicit default.
`)
}
