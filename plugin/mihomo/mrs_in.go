package mihomo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/klauspost/compress/zstd"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/provider"
)

const (
	TypeMihomoMRSIn = "mihomoMRS"
	DescMihomoMRSIn = "Load domain or IP/CIDR rules from mihomo binary rule-set (.mrs)"
)

var zstdMagicBytes = [4]byte{0x28, 0xB5, 0x2F, 0xFD}

func init() {
	lib.RegisterInputConfigCreator(TypeMihomoMRSIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewMRSInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeMihomoMRSIn, &mrsIn{
		Description: DescMihomoMRSIn,
	})
}

func IsMRSBytes(raw []byte) (P.RuleBehavior, bool) {
	if len(raw) < 4 || raw[0] != zstdMagicBytes[0] || raw[1] != zstdMagicBytes[1] || raw[2] != zstdMagicBytes[2] || raw[3] != zstdMagicBytes[3] {
		return 0, false
	}
	decoder, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		return 0, false
	}
	defer decoder.Close()

	var header [5]byte
	if _, err := io.ReadFull(decoder, header[:]); err != nil {
		return 0, false
	}
	if header[0] != provider.MrsMagicBytes[0] || header[1] != provider.MrsMagicBytes[1] || header[2] != provider.MrsMagicBytes[2] || header[3] != provider.MrsMagicBytes[3] {
		return 0, false
	}
	behavior := P.RuleBehavior(header[4])
	if behavior != P.Domain && behavior != P.IPCIDR {
		return 0, false
	}
	return behavior, true
}

func ParseMRSBytes(raw []byte, entry *lib.Entry, wantDomain, wantIP bool) (P.RuleBehavior, error) {
	behavior, ok := IsMRSBytes(raw)
	if !ok {
		return 0, fmt.Errorf("invalid mihomo MRS binary data")
	}

	var dumped bytes.Buffer
	if err := provider.ConvertToMrs(raw, behavior, P.MrsRule, &dumped); err != nil {
		return behavior, err
	}

	scanner := bufio.NewScanner(&dumped)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	switch behavior {
	case P.Domain:
		if !wantDomain {
			return behavior, nil
		}
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			switch {
			case strings.HasPrefix(line, "+."):
				entry.AddDomainRule(lib.DomainRule{
					Type:  lib.RuleTypeDomainSuffix,
					Value: strings.TrimPrefix(line, "+."),
				})
			case strings.HasPrefix(line, "."):
				entry.AddDomainRule(lib.DomainRule{
					Type:  lib.RuleTypeDomainSuffix,
					Value: strings.TrimPrefix(line, "."),
				})
			default:
				entry.AddDomainRule(lib.DomainRule{
					Type:  lib.RuleTypeDomain,
					Value: line,
				})
			}
		}
	case P.IPCIDR:
		if !wantIP {
			return behavior, nil
		}
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if err := entry.AddPrefix(line); err != nil {
				return behavior, err
			}
		}
	}

	return behavior, scanner.Err()
}

type mrsIn struct {
	Type        string
	Action      lib.Action
	Description string
	Names       []string
	URI         string
	FallbackURI string
	InputDir    string
	FallbackDir string
	Optional    bool
	Want        map[string]bool
	Exclude     map[string]bool
	OnlyIPType  lib.IPType
	S3Endpoint  string
	S3Region    string
	S3Bucket    string
}

func NewMRSInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name        string     `json:"name"`
		Names       []string   `json:"names"`
		URI         string     `json:"uri"`
		FallbackURI string     `json:"fallbackURI"`
		InputDir    string     `json:"inputDir"`
		FallbackDir string     `json:"fallbackDir"`
		Optional    bool       `json:"optional"`
		Want        []string   `json:"wantedList"`
		Exclude     []string   `json:"excludedList"`
		OnlyIPType  lib.IPType `json:"onlyIPType"`
		S3Endpoint  string     `json:"s3Endpoint"`
		S3Region    string     `json:"s3Region"`
		S3Bucket    string     `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeMihomoMRSIn, action, err)
		}
	}

	names := make([]string, 0, len(tmp.Names)+1)
	if n := strings.TrimSpace(tmp.Name); n != "" {
		names = append(names, n)
	}
	for _, n := range tmp.Names {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}

	m := &mrsIn{
		Type:        TypeMihomoMRSIn,
		Action:      action,
		Description: DescMihomoMRSIn,
		Names:       names,
		URI:         strings.TrimSpace(tmp.URI),
		FallbackURI: strings.TrimSpace(tmp.FallbackURI),
		InputDir:    strings.TrimSpace(tmp.InputDir),
		FallbackDir: strings.TrimSpace(tmp.FallbackDir),
		Optional:    tmp.Optional,
		Want:        toUpperSet(tmp.Want),
		Exclude:     toUpperSet(tmp.Exclude),
		OnlyIPType:  tmp.OnlyIPType,
		S3Endpoint:  strings.TrimSpace(tmp.S3Endpoint),
		S3Region:    strings.TrimSpace(tmp.S3Region),
		S3Bucket:    strings.TrimSpace(tmp.S3Bucket),
	}

	if m.InputDir == "" {
		if len(m.Names) == 0 || m.URI == "" {
			return nil, fmt.Errorf("[type %s | action %s] missing inputDir or (name/names and uri)", m.Type, m.Action)
		}
	} else if len(m.Names) > 0 || m.URI != "" {
		return nil, fmt.Errorf("[type %s | action %s] inputDir cannot be used with name or uri", m.Type, m.Action)
	}

	return m, nil
}

func (m *mrsIn) GetType() string {
	return m.Type
}

func (m *mrsIn) GetAction() lib.Action {
	return m.Action
}

func (m *mrsIn) GetDescription() string {
	return m.Description
}

func (m *mrsIn) Input(container lib.Container) (lib.Container, error) {
	if m.InputDir != "" {
		return m.inputFromDir(container)
	}

	raw, err := m.readURIWithFallback()
	if err != nil {
		if m.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
	}

	for _, name := range m.Names {
		if err := m.applyBytes(container, name, raw); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
		}
	}
	return container, nil
}

func (m *mrsIn) readURIWithFallback() ([]byte, error) {
	content, err := m.readURI(m.URI)
	if err != nil && m.FallbackURI != "" {
		return m.readURI(m.FallbackURI)
	}
	return content, err
}

func (m *mrsIn) readURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: m.S3Endpoint,
			Region:   m.S3Region,
			Bucket:   m.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (m *mrsIn) inputFromDir(container lib.Container) (lib.Container, error) {
	if lib.IsS3URI(m.InputDir) {
		err := m.inputFromS3Dir(container)
		if err == nil {
			return container, nil
		}
		if m.FallbackDir != "" {
			if fbErr := m.inputFromLocalDir(m.FallbackDir, container); fbErr != nil {
				if m.Optional {
					return container, nil
				}
				return nil, fmt.Errorf("[type %s | action %s] s3 failed (%v) and fallbackDir failed: %w", m.Type, m.Action, err, fbErr)
			}
			return container, nil
		}
		if m.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
	}

	if err := m.inputFromLocalDir(m.InputDir, container); err != nil {
		if m.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
	}
	return container, nil
}

func (m *mrsIn) inputFromS3Dir(container lib.Container) error {
	bucket, prefix, err := lib.ParseS3URI(m.InputDir)
	if err != nil {
		return err
	}
	cfg := lib.S3Config{
		Endpoint: m.S3Endpoint,
		Region:   m.S3Region,
		Bucket:   m.S3Bucket,
	}
	if bucket != "" {
		cfg.Bucket = bucket
	}
	client, err := lib.NewS3Client(cfg)
	if err != nil {
		return err
	}
	ctx := context.Background()
	keys, err := client.ListObjects(ctx, cfg.Bucket, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		base := path.Base(key)
		if !strings.EqualFold(path.Ext(base), ".mrs") {
			continue
		}
		name := strings.TrimSuffix(base, path.Ext(base))
		if !m.shouldLoad(name) {
			continue
		}
		raw, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		if err := m.applyBytes(container, name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (m *mrsIn) inputFromLocalDir(dir string, container lib.Container) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range dirEntries {
		if de.IsDir() || !strings.EqualFold(filepath.Ext(de.Name()), ".mrs") {
			continue
		}
		name := strings.TrimSuffix(de.Name(), filepath.Ext(de.Name()))
		if !m.shouldLoad(name) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			return err
		}
		if err := m.applyBytes(container, name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (m *mrsIn) shouldLoad(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	if len(m.Want) > 0 && !m.Want[upper] {
		return false
	}
	if m.Exclude[upper] {
		return false
	}
	return true
}

func (m *mrsIn) applyBytes(container lib.Container, name string, raw []byte) error {
	entry := lib.NewEntry(name)
	behavior, err := ParseMRSBytes(raw, entry, true, true)
	if err != nil {
		return err
	}
	kind := lib.EntryKindDomain
	if behavior == P.IPCIDR {
		kind = lib.EntryKindIP
	}
	ignoreIP := lib.GetIgnoreIPType(m.OnlyIPType)
	switch m.Action {
	case lib.ActionAdd:
		return container.Add(entry, ignoreIP)
	case lib.ActionReplace:
		return container.Replace(entry, kind, ignoreIP)
	case lib.ActionRemove:
		return container.Remove(entry, lib.CaseRemoveRule, kind, ignoreIP)
	default:
		return fmt.Errorf("unsupported action %s", m.Action)
	}
}

func toUpperSet(items []string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range items {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			m[item] = true
		}
	}
	return m
}
