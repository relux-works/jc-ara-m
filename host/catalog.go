package provisioner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	MaxRefArDOLength       = 96
	StandardPackageAIDHex  = "A00000015141434C"
	StandardInstanceAIDHex = "A00000015141434C00"
)

// RuleKey is the exact SEAC REF-DO identity used for desired/current matching.
type RuleKey struct {
	AID         []byte
	DeviceAppID []byte
}

func (k RuleKey) mapKey() string {
	encoded := make([]byte, 0, 2+len(k.AID)+len(k.DeviceAppID))
	encoded = append(encoded, byte(len(k.AID)))
	encoded = append(encoded, k.AID...)
	encoded = append(encoded, byte(len(k.DeviceAppID)))
	encoded = append(encoded, k.DeviceAppID...)
	return string(encoded)
}

func (k RuleKey) Identifier() string {
	digest := sha256.Sum256([]byte(k.mapKey()))
	return hex.EncodeToString(digest[:8])
}

// Rule contains one complete, validated REF-AR-DO (E2) and its exact REF-DO.
type Rule struct {
	Bytes    []byte
	RefDO    []byte
	Key      RuleKey
	APDURule []byte
}

func (r Rule) Identifier() string {
	digest := sha256.Sum256(r.Bytes)
	return hex.EncodeToString(digest[:8])
}

// IsCatchAll reports whether the rule's REF-DO carries the zero-length
// AID-REF-DO that matches every SE applet.
func (r Rule) IsCatchAll() bool {
	return len(r.Key.AID) == 0
}

// GrantsAccess reports whether the rule's APDU-AR-DO grants any access. Only
// the generic never-allowed rule (D0 01 00) grants nothing; the generic
// always-allowed rule and every APDU filter list permit at least one command.
func (r Rule) GrantsAccess() bool {
	return !(len(r.APDURule) == 1 && r.APDURule[0] == 0x00)
}

type CatalogSnapshot struct {
	Rules      []Rule
	RefreshTag []byte
}

// ParseRule validates the bounded APDU-only profile implemented by the applet.
func ParseRule(input []byte) (Rule, error) {
	if len(input) == 0 || len(input) > MaxRefArDOLength {
		return Rule{}, fmt.Errorf("REF-AR-DO length %d is outside 1..%d", len(input), MaxRefArDOLength)
	}
	tag, value, next, err := readTLV(input, 0)
	if err != nil {
		return Rule{}, fmt.Errorf("REF-AR-DO: %w", err)
	}
	if tag != 0xE2 || next != len(input) {
		return Rule{}, errors.New("rule must be exactly one complete E2 REF-AR-DO")
	}

	refTag, refValue, refEnd, err := readTLV(value, 0)
	if err != nil {
		return Rule{}, fmt.Errorf("REF-DO: %w", err)
	}
	if refTag != 0xE1 {
		return Rule{}, fmt.Errorf("expected E1 REF-DO, got %02X", refTag)
	}
	aidTag, aid, cursor, err := readTLV(refValue, 0)
	if err != nil {
		return Rule{}, fmt.Errorf("AID-REF-DO: %w", err)
	}
	// A zero-length AID-REF-DO is the SEAC catch-all reference matching every SE
	// applet. It is a valid store shape; whether a catch-all may grant access is
	// a host policy decision enforced when a plan is built, not here.
	if aidTag != 0x4F || (len(aid) != 0 && (len(aid) < 5 || len(aid) > 16)) {
		return Rule{}, fmt.Errorf("AID-REF-DO must be tag 4F with length 0 or 5..16, got tag %02X length %d", aidTag, len(aid))
	}
	deviceTag, device, deviceEnd, err := readTLV(refValue, cursor)
	if err != nil {
		return Rule{}, fmt.Errorf("DeviceAppID-REF-DO: %w", err)
	}
	if deviceTag != 0xC1 || (len(device) != 0 && len(device) != 20 && len(device) != 32) {
		return Rule{}, fmt.Errorf("DeviceAppID-REF-DO must be tag C1 with length 0, 20, or 32, got tag %02X length %d", deviceTag, len(device))
	}
	if deviceEnd != len(refValue) {
		return Rule{}, errors.New("REF-DO contains trailing data")
	}

	arTag, arValue, arEnd, err := readTLV(value, refEnd)
	if err != nil {
		return Rule{}, fmt.Errorf("AR-DO: %w", err)
	}
	if arTag != 0xE3 || arEnd != len(value) {
		return Rule{}, fmt.Errorf("expected one trailing E3 AR-DO, got tag %02X", arTag)
	}
	apduTag, apduRule, apduEnd, err := readTLV(arValue, 0)
	if err != nil {
		return Rule{}, fmt.Errorf("APDU-AR-DO: %w", err)
	}
	if apduTag != 0xD0 || apduEnd != len(arValue) {
		return Rule{}, fmt.Errorf("AR-DO must contain exactly one D0 APDU-AR-DO, got tag %02X", apduTag)
	}
	if len(apduRule) == 1 {
		if apduRule[0] != 0x00 && apduRule[0] != 0x01 {
			return Rule{}, fmt.Errorf("generic APDU rule must be 00 or 01, got %02X", apduRule[0])
		}
	} else if len(apduRule) == 0 || len(apduRule)%8 != 0 {
		return Rule{}, fmt.Errorf("APDU filter rule length %d is not 1 or a positive multiple of 8", len(apduRule))
	}

	refDoBytes := append([]byte(nil), value[:refEnd]...)
	return Rule{
		Bytes:    append([]byte(nil), input...),
		RefDO:    refDoBytes,
		APDURule: append([]byte(nil), apduRule...),
		Key: RuleKey{
			AID:         append([]byte(nil), aid...),
			DeviceAppID: append([]byte(nil), device...),
		},
	}, nil
}

// ParseFF40Catalog parses a complete FF40 wrapper and all concatenated E2 rules.
func ParseFF40Catalog(input []byte) (CatalogSnapshot, error) {
	tag, value, end, err := readTLV(input, 0)
	if err != nil {
		return CatalogSnapshot{}, fmt.Errorf("FF40: %w", err)
	}
	if tag != 0xFF40 || end != len(input) {
		return CatalogSnapshot{}, errors.New("catalog must be exactly one complete FF40 object")
	}
	rules := make([]Rule, 0)
	for cursor := 0; cursor < len(value); {
		tag, _, next, err := readTLV(value, cursor)
		if err != nil {
			return CatalogSnapshot{}, fmt.Errorf("catalog rule %d: %w", len(rules), err)
		}
		if tag != 0xE2 {
			return CatalogSnapshot{}, fmt.Errorf("catalog rule %d has tag %02X, want E2", len(rules), tag)
		}
		rule, err := ParseRule(value[cursor:next])
		if err != nil {
			return CatalogSnapshot{}, fmt.Errorf("catalog rule %d: %w", len(rules), err)
		}
		rules = append(rules, rule)
		cursor = next
	}
	return CatalogSnapshot{Rules: rules}, nil
}

func NormalizeRules(rules []Rule, capacity int) ([]Rule, error) {
	if capacity <= 0 {
		return nil, errors.New("capacity must be positive")
	}
	if len(rules) > capacity {
		return nil, fmt.Errorf("catalog has %d rules, installed capacity is %d", len(rules), capacity)
	}
	seen := make(map[string]struct{}, len(rules))
	normalized := make([]Rule, len(rules))
	for i, rule := range rules {
		parsed, err := ParseRule(rule.Bytes)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		key := parsed.Key.mapKey()
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate exact REF-DO key %s", parsed.Key.Identifier())
		}
		seen[key] = struct{}{}
		normalized[i] = parsed
	}
	sort.Slice(normalized, func(i, j int) bool {
		return compareKeys(normalized[i].Key, normalized[j].Key) < 0
	})
	return normalized, nil
}

func compareKeys(left, right RuleKey) int {
	if compared := bytes.Compare(left.AID, right.AID); compared != 0 {
		return compared
	}
	if len(left.DeviceAppID) < len(right.DeviceAppID) {
		return -1
	}
	if len(left.DeviceAppID) > len(right.DeviceAppID) {
		return 1
	}
	return bytes.Compare(left.DeviceAppID, right.DeviceAppID)
}

type Manifest struct {
	Capacity int            `json:"capacity"`
	Rules    []ManifestRule `json:"rules"`
}

type ManifestRule struct {
	RefArDO string `json:"ref_ar_do"`
}

func LoadManifest(path string) ([]Rule, int, error) {
	file, err := openSecureInput(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, 0, fmt.Errorf("decode manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, 0, err
	}
	rules := make([]Rule, len(manifest.Rules))
	for i, encoded := range manifest.Rules {
		bytesValue, err := hex.DecodeString(strings.TrimSpace(encoded.RefArDO))
		if err != nil {
			return nil, 0, fmt.Errorf("rules[%d].ref_ar_do: %w", i, err)
		}
		rules[i], err = ParseRule(bytesValue)
		if err != nil {
			return nil, 0, fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	normalized, err := NormalizeRules(rules, manifest.Capacity)
	if err != nil {
		return nil, 0, err
	}
	return normalized, manifest.Capacity, nil
}

func SaveManifest(path string, rules []Rule, capacity int) error {
	normalized, err := NormalizeRules(rules, capacity)
	if err != nil {
		return err
	}
	manifest := Manifest{Capacity: capacity, Rules: make([]ManifestRule, len(normalized))}
	for i := range normalized {
		manifest.Rules[i].RefArDO = strings.ToUpper(hex.EncodeToString(normalized[i].Bytes))
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	return writeFileAtomic0600(path, encoded)
}

func openSecureInput(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s contains rule/credential material and must not be accessible by group or other users", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return file, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("input contains more than one JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func writeFileAtomic0600(path string, data []byte) error {
	directory := "."
	if split := strings.LastIndexByte(path, '/'); split >= 0 {
		directory = path[:split]
		if directory == "" {
			directory = "/"
		}
	}
	temporary, err := os.CreateTemp(directory, ".aram-provisioner-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func readTLV(input []byte, offset int) (tag uint16, value []byte, next int, err error) {
	if offset < 0 || offset >= len(input) {
		return 0, nil, offset, errors.New("missing tag")
	}
	tag = uint16(input[offset])
	cursor := offset + 1
	if input[offset]&0x1F == 0x1F {
		if cursor >= len(input) || input[cursor]&0x80 != 0 {
			return 0, nil, offset, errors.New("unsupported multi-byte tag")
		}
		tag = tag<<8 | uint16(input[cursor])
		cursor++
	}
	length, afterLength, err := readBERLength(input, cursor)
	if err != nil {
		return 0, nil, offset, err
	}
	end := afterLength + length
	if end < afterLength || end > len(input) {
		return 0, nil, offset, fmt.Errorf("declared length %d exceeds remaining %d", length, len(input)-afterLength)
	}
	return tag, input[afterLength:end], end, nil
}

func readBERLength(input []byte, offset int) (length int, next int, err error) {
	if offset < 0 || offset >= len(input) {
		return 0, offset, errors.New("missing BER length")
	}
	first := input[offset]
	if first < 0x80 {
		return int(first), offset + 1, nil
	}
	count := int(first & 0x7F)
	if count == 0 || count > 2 || offset+1+count > len(input) {
		return 0, offset, errors.New("unsupported or truncated BER length")
	}
	if input[offset+1] == 0 {
		return 0, offset, errors.New("non-minimal BER length")
	}
	length = 0
	for i := 0; i < count; i++ {
		length = length<<8 | int(input[offset+1+i])
	}
	if length < 0x80 || (length <= 0xFF && count != 1) {
		return 0, offset, errors.New("non-minimal BER length")
	}
	return length, offset + 1 + count, nil
}

func encodeBERLength(length int) ([]byte, error) {
	switch {
	case length < 0:
		return nil, errors.New("negative BER length")
	case length < 0x80:
		return []byte{byte(length)}, nil
	case length <= 0xFF:
		return []byte{0x81, byte(length)}, nil
	case length <= 0xFFFF:
		return []byte{0x82, byte(length >> 8), byte(length)}, nil
	default:
		return nil, errors.New("BER length exceeds 65535")
	}
}
