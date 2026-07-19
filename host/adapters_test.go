package provisioner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestJCHarnessReaderCollectsFF40AndFF60(t *testing.T) {
	ruleA := testRule(t, "F0000000AA01", "", 0x01)
	ruleB := testRule(t, "F0000000BB01", "", 0x01)
	value := append(append([]byte(nil), ruleA.Bytes...), ruleB.Bytes...)
	first := append([]byte{0xFF, 0x40, byte(len(value))}, value[:10]...)

	results := []map[string]string{
		{"sw": "9000", "data": ""},
		{"sw": "9000", "data": hexUpper(first)},
		{"sw": "9000", "data": hexUpper(value[10:])},
		{"sw": "6985", "data": ""},
		{"sw": "9000", "data": "DF20080000000000000001"},
	}
	payload, err := json.Marshal(map[string]any{"reader": "test", "results": results})
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{output: payload}
	reader := JCHarnessReader{
		Runner:      runner,
		Binary:      "jc-harness",
		Reader:      "OMNIKEY",
		InstanceAID: mustHex(t, StandardInstanceAIDHex),
		Capacity:    2,
	}

	snapshot, err := reader.ReadCatalog(context.Background())
	if err != nil {
		t.Fatalf("ReadCatalog: %v", err)
	}
	if len(snapshot.Rules) != 2 || len(snapshot.RefreshTag) != 8 {
		t.Fatalf("snapshot rules=%d refresh=%d", len(snapshot.Rules), len(snapshot.RefreshTag))
	}
	if runner.name != "jc-harness" || !containsArg(runner.args, "seq") {
		t.Fatalf("unexpected invocation: %s %v", runner.name, runner.args)
	}
}

func TestGPHelperSinkUsesOnlyAuthenticatedSecureAPDUPath(t *testing.T) {
	rule := testRule(t, "F0000000AA01", "", 0x01)
	plan, err := PlanDiff(nil, []Rule{rule}, 16)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	sink := GPHelperSink{
		Runner:      runner,
		Binary:      "gp-t0-helper",
		InstanceAID: mustHex(t, StandardInstanceAIDHex),
		Credentials: SDCredentials{
			KIC:        "00112233445566778899AABBCCDDEEFF",
			KID:        "00112233445566778899AABBCCDDEEFF",
			KIK:        "00112233445566778899AABBCCDDEEFF",
			KeyVersion: "20",
			SCP:        "SCP02",
			I:          "15",
		},
	}

	if err := sink.Apply(context.Background(), plan.Mutations); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if runner.name != "gp-t0-helper" || len(runner.args) == 0 || runner.args[0] != "secure-apdu" {
		t.Fatalf("mutation did not use secure-apdu: %s %v", runner.name, runner.args)
	}
	for _, arg := range runner.args {
		if arg == "apdu" {
			t.Fatal("raw gp-t0-helper apdu path was used")
		}
	}
	if got := len(runner.args) - 7; got != 2 {
		t.Fatalf("authenticated APDU count = %d, want personalization + one F0", got)
	}
}

func TestLoadCredentialsRequiresSecureValidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	contents := []byte(`{"kic":"00112233445566778899AABBCCDDEEFF","kid":"00112233445566778899AABBCCDDEEFF","kik":"00112233445566778899AABBCCDDEEFF","key_version":"20","scp":"SCP02","i":"15"}`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if credentials.SCP != "SCP02" {
		t.Fatalf("SCP = %s", credentials.SCP)
	}
	credentials.SCP = "SCP99"
	if err := credentials.Validate(); err == nil {
		t.Fatal("Validate accepted an unsupported SCP")
	}
}

type recordingRunner struct {
	name   string
	args   []string
	output []byte
	err    error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return append([]byte(nil), r.output...), r.err
}

func containsArg(args []string, expected string) bool {
	for _, arg := range args {
		if arg == expected {
			return true
		}
	}
	return false
}

func hexUpper(value []byte) string {
	const digits = "0123456789ABCDEF"
	var builder strings.Builder
	builder.Grow(len(value) * 2)
	for _, b := range value {
		builder.WriteByte(digits[b>>4])
		builder.WriteByte(digits[b&0x0F])
	}
	return builder.String()
}

var _ CommandRunner = (*recordingRunner)(nil)

func TestCanonicalOrderingUsesAIDThenDeviceLengthThenBytes(t *testing.T) {
	rules := []Rule{
		testRule(t, "F0000000AA01", make([]byte, 32), 0x01),
		testRule(t, "F0000000AB01", "", 0x01),
		testRule(t, "F0000000AA01", "", 0x01),
		testRule(t, "F0000000AA01", make([]byte, 20), 0x01),
	}
	normalized, err := NormalizeRules(rules, 16)
	if err != nil {
		t.Fatal(err)
	}
	lengths := make([]int, len(normalized))
	for i := range normalized {
		lengths[i] = len(normalized[i].Key.DeviceAppID)
	}
	if want := []int{0, 20, 32, 0}; !reflect.DeepEqual(lengths, want) {
		t.Fatalf("DeviceAppID lengths = %v, want %v", lengths, want)
	}
}
