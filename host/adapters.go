package provisioner

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("%s exited unsuccessfully", name)
	}
	return output, nil
}

type JCHarnessReader struct {
	Runner      CommandRunner
	Binary      string
	Reader      string
	InstanceAID []byte
	Capacity    int
}

type jcHarnessSequence struct {
	Reader  string              `json:"reader"`
	Results []jcHarnessResponse `json:"results"`
}

type jcHarnessResponse struct {
	SW   string `json:"sw"`
	Data string `json:"data"`
}

func (r JCHarnessReader) ReadCatalog(ctx context.Context) (CatalogSnapshot, error) {
	if r.Runner == nil || r.Binary == "" || r.Reader == "" {
		return CatalogSnapshot{}, errors.New("jc-harness runner, binary, and reader are required")
	}
	if len(r.InstanceAID) < 5 || len(r.InstanceAID) > 16 || r.Capacity <= 0 {
		return CatalogSnapshot{}, errors.New("valid ARA-M instance AID and positive capacity are required")
	}
	selectAPDU := []byte{0x00, 0xA4, 0x04, 0x00, byte(len(r.InstanceAID))}
	selectAPDU = append(selectAPDU, r.InstanceAID...)
	apdus := []string{hexUpperBytes(selectAPDU), "80CAFF4000"}
	for i := 0; i < r.Capacity; i++ {
		apdus = append(apdus, "80CAFF6000")
	}
	apdus = append(apdus, "80CADF2000")
	output, err := r.Runner.Run(ctx, r.Binary, "seq", "--reader", r.Reader, "--apdu", strings.Join(apdus, ","))
	if err != nil {
		return CatalogSnapshot{}, errors.New("jc-harness catalog sequence failed")
	}
	var sequence jcHarnessSequence
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sequence); err != nil {
		return CatalogSnapshot{}, fmt.Errorf("decode jc-harness response: %w", err)
	}
	if len(sequence.Results) != len(apdus) {
		return CatalogSnapshot{}, fmt.Errorf("jc-harness returned %d results, want %d", len(sequence.Results), len(apdus))
	}
	if normalizeSW(sequence.Results[0].SW) != "9000" {
		return CatalogSnapshot{}, fmt.Errorf("ARA-M SELECT returned SW=%s", sanitizeSW(sequence.Results[0].SW))
	}
	firstData, err := decodeResponseData(sequence.Results[1])
	if err != nil {
		return CatalogSnapshot{}, fmt.Errorf("FF40: %w", err)
	}
	totalLength, headerLength, err := parseFF40Prefix(firstData)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	value := append([]byte(nil), firstData[headerLength:]...)
	if len(value) > totalLength {
		return CatalogSnapshot{}, errors.New("FF40 first response exceeds advertised catalog length")
	}
	for index := 0; len(value) < totalLength && index < r.Capacity; index++ {
		response := sequence.Results[2+index]
		if normalizeSW(response.SW) != "9000" {
			return CatalogSnapshot{}, fmt.Errorf("FF60 chunk %d returned SW=%s before catalog completed", index, sanitizeSW(response.SW))
		}
		chunk, err := decodeResponseData(response)
		if err != nil {
			return CatalogSnapshot{}, fmt.Errorf("FF60 chunk %d: %w", index, err)
		}
		if len(chunk) == 0 || len(value)+len(chunk) > totalLength {
			return CatalogSnapshot{}, fmt.Errorf("FF60 chunk %d has invalid length %d", index, len(chunk))
		}
		value = append(value, chunk...)
	}
	if len(value) != totalLength {
		return CatalogSnapshot{}, fmt.Errorf("catalog continuation incomplete: got %d of %d bytes", len(value), totalLength)
	}
	lengthBytes, err := encodeBERLength(totalLength)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	wrapper := append([]byte{0xFF, 0x40}, lengthBytes...)
	wrapper = append(wrapper, value...)
	snapshot, err := ParseFF40Catalog(wrapper)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	refreshResponse := sequence.Results[len(sequence.Results)-1]
	refreshData, err := decodeResponseData(refreshResponse)
	if err != nil {
		return CatalogSnapshot{}, fmt.Errorf("DF20: %w", err)
	}
	if len(refreshData) != 11 || refreshData[0] != 0xDF || refreshData[1] != 0x20 || refreshData[2] != 0x08 {
		return CatalogSnapshot{}, errors.New("DF20 response is not one eight-byte refresh object")
	}
	snapshot.RefreshTag = append([]byte(nil), refreshData[3:]...)
	return snapshot, nil
}

func parseFF40Prefix(data []byte) (totalLength, headerLength int, err error) {
	if len(data) < 3 || data[0] != 0xFF || data[1] != 0x40 {
		return 0, 0, errors.New("FF40 response is missing the FF40 tag")
	}
	length, next, err := readBERLength(data, 2)
	if err != nil {
		return 0, 0, fmt.Errorf("FF40 length: %w", err)
	}
	return length, next, nil
}

func decodeResponseData(response jcHarnessResponse) ([]byte, error) {
	if normalizeSW(response.SW) != "9000" {
		return nil, fmt.Errorf("returned SW=%s", sanitizeSW(response.SW))
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(response.Data))
	if err != nil {
		return nil, errors.New("returned malformed hex data")
	}
	return decoded, nil
}

func normalizeSW(sw string) string {
	return strings.ToUpper(strings.TrimSpace(sw))
}

func sanitizeSW(sw string) string {
	normalized := normalizeSW(sw)
	if len(normalized) == 4 {
		if _, err := hex.DecodeString(normalized); err == nil {
			return normalized
		}
	}
	return "invalid"
}

type SDCredentials struct {
	KIC        string `json:"kic"`
	KID        string `json:"kid"`
	KIK        string `json:"kik"`
	KeyVersion string `json:"key_version"`
	SCP        string `json:"scp"`
	I          string `json:"i"`
}

func LoadCredentials(path string) (SDCredentials, error) {
	file, err := openSecureInput(path)
	if err != nil {
		return SDCredentials{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var credentials SDCredentials
	if err := decoder.Decode(&credentials); err != nil {
		return SDCredentials{}, fmt.Errorf("decode credentials: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SDCredentials{}, err
	}
	if err := credentials.Validate(); err != nil {
		return SDCredentials{}, err
	}
	return credentials, nil
}

func (c SDCredentials) Validate() error {
	for name, value := range map[string]string{"kic": c.KIC, "kid": c.KID, "kik": c.KIK} {
		decoded, err := hex.DecodeString(value)
		if err != nil || (len(decoded) != 16 && len(decoded) != 24 && len(decoded) != 32) {
			return fmt.Errorf("%s must be a 16-, 24-, or 32-byte hex key", name)
		}
	}
	if decoded, err := hex.DecodeString(c.KeyVersion); err != nil || len(decoded) != 1 {
		return errors.New("key_version must be one hex byte")
	}
	if c.SCP != "SCP02" && c.SCP != "SCP03" {
		return errors.New("scp must be SCP02 or SCP03")
	}
	if decoded, err := hex.DecodeString(c.I); err != nil || len(decoded) != 1 {
		return errors.New("i must be one hex byte")
	}
	return nil
}

type GPHelperSink struct {
	Runner      CommandRunner
	Binary      string
	InstanceAID []byte
	Credentials SDCredentials
}

func (s GPHelperSink) Apply(ctx context.Context, mutations []Mutation) error {
	if len(mutations) == 0 {
		return nil
	}
	if s.Runner == nil || s.Binary == "" {
		return errors.New("gp-t0-helper runner and binary are required")
	}
	if err := s.Credentials.Validate(); err != nil {
		return err
	}
	personalization, err := personalizationAPDU(s.InstanceAID)
	if err != nil {
		return err
	}
	args := []string{
		"secure-apdu",
		s.Credentials.KIC,
		s.Credentials.KID,
		s.Credentials.KIK,
		s.Credentials.KeyVersion,
		s.Credentials.SCP,
		s.Credentials.I,
		hexUpperBytes(personalization),
	}
	for _, mutation := range mutations {
		if len(mutation.APDU) == 0 {
			return errors.New("mutation is missing its STORE DATA APDU")
		}
		args = append(args, hexUpperBytes(mutation.APDU))
	}
	if _, err := s.Runner.Run(ctx, s.Binary, args...); err != nil {
		return errors.New("gp-t0-helper authenticated secure-apdu manifest failed")
	}
	return nil
}

func personalizationAPDU(instanceAID []byte) ([]byte, error) {
	if len(instanceAID) < 5 || len(instanceAID) > 16 {
		return nil, errors.New("ARA-M instance AID length must be 5..16")
	}
	data := []byte{0x00, 0x00, byte(len(instanceAID))}
	data = append(data, instanceAID...)
	data = append(data, 0x00, 0x00, 0x00)
	apdu := []byte{0x80, 0xE6, 0x20, 0x00, byte(len(data))}
	apdu = append(apdu, data...)
	return apdu, nil
}

func hexUpperBytes(value []byte) string {
	return strings.ToUpper(hex.EncodeToString(value))
}
