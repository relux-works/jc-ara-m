package provisioner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestRoundTripUsesSecureAtomicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	rules := []Rule{
		testRule(t, "F0000000AA01", "", 0x01),
		testRule(t, "F0000000BB01", bytes.Repeat([]byte{0x42}, 20), 0x00),
	}
	if err := SaveManifest(path, rules, 16); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("manifest mode = %o, want 600", got)
	}
	loaded, capacity, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if capacity != 16 || len(loaded) != 2 {
		t.Fatalf("capacity=%d rules=%d", capacity, len(loaded))
	}
	if !bytes.Equal(loaded[0].Bytes, rules[0].Bytes) || !bytes.Equal(loaded[1].Bytes, rules[1].Bytes) {
		t.Fatal("manifest round trip changed rules")
	}
}

func TestLoadManifestRejectsLoosePermissionsAndTrailingJSON(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"capacity":16,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadManifest(path); err == nil {
		t.Fatal("LoadManifest accepted group/world-readable policy material")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"capacity":16,"rules":[]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadManifest(path); err == nil {
		t.Fatal("LoadManifest accepted trailing JSON")
	}
}

func TestBERLengthBoundaries(t *testing.T) {
	for _, length := range []int{0, 127, 128, 255, 256, 65535} {
		encoded, err := encodeBERLength(length)
		if err != nil {
			t.Fatalf("encodeBERLength(%d): %v", length, err)
		}
		decoded, next, err := readBERLength(encoded, 0)
		if err != nil {
			t.Fatalf("readBERLength(%d): %v", length, err)
		}
		if decoded != length || next != len(encoded) {
			t.Fatalf("length %d round trip -> %d/%d", length, decoded, next)
		}
	}
	for _, invalid := range [][]byte{{0x80}, {0x83, 0x01, 0x00, 0x00}, {0x81, 0x7F}, {0x82, 0x00, 0x80}} {
		if _, _, err := readBERLength(invalid, 0); err == nil {
			t.Fatalf("readBERLength accepted %X", invalid)
		}
	}
}

func TestPlanSummaryContainsOnlySanitizedIdentifiers(t *testing.T) {
	rule := testRule(t, "F0000000AA01", bytes.Repeat([]byte{0x99}, 32), 0x01)
	plan, err := PlanDiff(nil, []Rule{rule}, 16)
	if err != nil {
		t.Fatal(err)
	}
	summary := plan.Summary()
	if summary.CommandCount != 1 || len(summary.Mutations[0].KeyID) != 16 || len(summary.Mutations[0].RuleID) != 16 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}
