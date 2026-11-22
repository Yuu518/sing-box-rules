package plaintext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"go.yaml.in/yaml/v3"
)

const (
	TypeMihomoDomainIn = "mihomoDomain"
	DescMihomoDomainIn = "Load domain rules from mihomo/Clash YAML payload or domain text format"
)

func init() {
	lib.RegisterInputConfigCreator(TypeMihomoDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewMihomoDomainInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeMihomoDomainIn, &mihomoDomainIn{
		Description: DescMihomoDomainIn,
	})
}

type mihomoDomainIn struct {
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
	S3Endpoint  string
	S3Region    string
	S3Bucket    string
}

func NewMihomoDomainInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name        string   `json:"name"`
		Names       []string `json:"names"`
		URI         string   `json:"uri"`
		FallbackURI string   `json:"fallbackURI"`
		InputDir    string   `json:"inputDir"`
		FallbackDir string   `json:"fallbackDir"`
		Optional    bool     `json:"optional"`
		Want        []string `json:"wantedList"`
		Exclude     []string `json:"excludedList"`
		S3Endpoint  string   `json:"s3Endpoint"`
		S3Region    string   `json:"s3Region"`
		S3Bucket    string   `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeMihomoDomainIn, action, err)
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

	m := &mihomoDomainIn{
		Type:        TypeMihomoDomainIn,
		Action:      action,
		Description: DescMihomoDomainIn,
		Names:       names,
		URI:         strings.TrimSpace(tmp.URI),
		FallbackURI: strings.TrimSpace(tmp.FallbackURI),
		InputDir:    strings.TrimSpace(tmp.InputDir),
		FallbackDir: strings.TrimSpace(tmp.FallbackDir),
		Optional:    tmp.Optional,
		Want:        toUpperMap(tmp.Want),
		Exclude:     toUpperMap(tmp.Exclude),
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

func (m *mihomoDomainIn) GetType() string {
	return m.Type
}

func (m *mihomoDomainIn) GetAction() lib.Action {
	return m.Action
}

func (m *mihomoDomainIn) GetDescription() string {
	return m.Description
}

func (m *mihomoDomainIn) Input(container lib.Container) (lib.Container, error) {
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

	rules := parseMihomoDomainBytes(raw)
	for _, name := range m.Names {
		if err := m.applyRules(container, name, rules); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
		}
	}
	return container, nil
}

func (m *mihomoDomainIn) readURIWithFallback() ([]byte, error) {
	content, err := m.readURI(m.URI)
	if err != nil && m.FallbackURI != "" {
		return m.readURI(m.FallbackURI)
	}
	return content, err
}

func (m *mihomoDomainIn) readURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: m.S3Endpoint,
			Region:   m.S3Region,
			Bucket:   m.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (m *mihomoDomainIn) inputFromDir(container lib.Container) (lib.Container, error) {
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

func (m *mihomoDomainIn) inputFromS3Dir(container lib.Container) error {
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
		if strings.HasPrefix(base, ".") {
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
		if err := m.applyRules(container, name, parseMihomoDomainBytes(raw)); err != nil {
			return err
		}
	}
	return nil
}

func (m *mihomoDomainIn) inputFromLocalDir(dir string, container lib.Container) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range dirEntries {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
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
		if err := m.applyRules(container, name, parseMihomoDomainBytes(raw)); err != nil {
			return err
		}
	}
	return nil
}

func (m *mihomoDomainIn) shouldLoad(name string) bool {
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

func (m *mihomoDomainIn) applyRules(container lib.Container, name string, rules []lib.DomainRule) error {
	entry := lib.NewEntry(name)
	for _, r := range rules {
		entry.AddDomainRule(r)
	}
	switch m.Action {
	case lib.ActionAdd:
		return container.Add(entry)
	case lib.ActionReplace:
		return container.Replace(entry, lib.EntryKindDomain)
	case lib.ActionRemove:
		return container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindDomain)
	default:
		return fmt.Errorf("unsupported action %s", m.Action)
	}
}

func parseMihomoDomainBytes(raw []byte) []lib.DomainRule {
	var doc struct {
		Payload []string `yaml:"payload"`
	}
	var items []string
	if err := yaml.Unmarshal(raw, &doc); err == nil && len(doc.Payload) > 0 {
		items = doc.Payload
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			line, _, _ = strings.Cut(line, "#")
			line = strings.TrimSpace(line)
			if line == "" || line == "payload:" {
				continue
			}
			items = append(items, line)
		}
	}

	var rules []lib.DomainRule
	for _, item := range items {
		if rule, ok := parseMihomoDomainItem(item); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

func parseMihomoDomainItem(raw string) (lib.DomainRule, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return lib.DomainRule{}, false
	}
	if strings.Contains(line, ",") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			return lib.DomainRule{}, false
		}
		kind := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			return lib.DomainRule{}, false
		}
		switch kind {
		case "DOMAIN":
			return lib.DomainRule{Type: lib.RuleTypeDomain, Value: strings.ToLower(val)}, true
		case "DOMAIN-SUFFIX":
			return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: strings.ToLower(strings.TrimPrefix(val, "."))}, true
		case "DOMAIN-KEYWORD":
			return lib.DomainRule{Type: lib.RuleTypeDomainKeyword, Value: strings.ToLower(val)}, true
		case "DOMAIN-REGEX":
			return lib.DomainRule{Type: lib.RuleTypeDomainRegex, Value: val}, true
		default:
			return lib.DomainRule{}, false
		}
	}

	if strings.HasPrefix(line, "+.") || strings.HasPrefix(line, "*.") || strings.HasPrefix(line, ".") {
		val := strings.TrimPrefix(line, "+.")
		val = strings.TrimPrefix(val, "*.")
		val = strings.TrimPrefix(val, ".")
		val = strings.ToLower(strings.TrimSpace(val))
		if !lib.IsValidDomainOrTLD(val) {
			return lib.DomainRule{}, false
		}
		return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val}, true
	}

	val := strings.ToLower(line)
	if !lib.IsValidDomainOrTLD(val) {
		return lib.DomainRule{}, false
	}
	return lib.DomainRule{Type: lib.RuleTypeDomain, Value: val}, true
}
