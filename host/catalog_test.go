package provisioner

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParseRuleAndCatalog(t *testing.T) {
	ruleA := testRule(t, "F0000000AA01", "", 0x01)
	ruleB := testRule(t, "F0000000AA01", bytes.Repeat([]byte{0x22}, 32), 0x00)

	parsed, err := ParseRule(ruleA.Bytes)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !bytes.Equal(parsed.Key.AID, mustHex(t, "F0000000AA01")) {
		t.Fatalf("AID mismatch: %X", parsed.Key.AID)
	}
	if len(parsed.Key.DeviceAppID) != 0 {
		t.Fatalf("unexpected DeviceAppID length: %d", len(parsed.Key.DeviceAppID))
	}

	wrapped := append([]byte{0xFF, 0x40, byte(len(ruleA.Bytes) + len(ruleB.Bytes))}, ruleA.Bytes...)
	wrapped = append(wrapped, ruleB.Bytes...)
	catalog, err := ParseFF40Catalog(wrapped)
	if err != nil {
		t.Fatalf("ParseFF40Catalog: %v", err)
	}
	if len(catalog.Rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(catalog.Rules))
	}
}

func TestParseRuleRejectsOutOfProfileAndTrailingData(t *testing.T) {
	valid := testRule(t, "F0000000AA01", "", 0x01)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "short aid", data: buildRule(mustHex(t, "A0000000"), nil, 0x01)},
		{name: "bad device app id", data: buildRule(mustHex(t, "F0000000AA01"), []byte{0x01}, 0x01)},
		{name: "trailing data", data: append(append([]byte(nil), valid.Bytes...), 0x00)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRule(tt.data); err == nil {
				t.Fatal("ParseRule unexpectedly succeeded")
			}
		})
	}
}

func TestNormalizeRejectsDuplicateExactRefDo(t *testing.T) {
	rule := testRule(t, "F0000000AA01", "", 0x01)
	if _, err := NormalizeRules([]Rule{rule, rule}, 16); err == nil {
		t.Fatal("NormalizeRules unexpectedly accepted a duplicate key")
	}
}

func testRule(t *testing.T, aidHex string, device any, access byte) Rule {
	t.Helper()
	var deviceBytes []byte
	switch value := device.(type) {
	case string:
		deviceBytes = mustHex(t, value)
	case []byte:
		deviceBytes = append([]byte(nil), value...)
	default:
		t.Fatalf("unsupported DeviceAppID type %T", device)
	}
	rule, err := ParseRule(buildRule(mustHex(t, aidHex), deviceBytes, access))
	if err != nil {
		t.Fatalf("ParseRule(test fixture): %v", err)
	}
	return rule
}

func buildRule(aid, device []byte, access byte) []byte {
	refValue := append([]byte{0x4F, byte(len(aid))}, aid...)
	refValue = append(refValue, 0xC1, byte(len(device)))
	refValue = append(refValue, device...)
	refDo := append([]byte{0xE1, byte(len(refValue))}, refValue...)
	arDo := []byte{0xE3, 0x03, 0xD0, 0x01, access}
	value := append(refDo, arDo...)
	return append([]byte{0xE2, byte(len(value))}, value...)
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return decoded
}
