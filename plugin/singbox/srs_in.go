package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	TypeSingboxSRSIn = "singboxSRS"
	DescSingboxSRSIn = "Load domain, AdGuard, and IP rules from sing-box binary rule-set (.srs)"
)

func init() {
	lib.RegisterInputConfigCreator(TypeSingboxSRSIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewSRSInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeSingboxSRSIn, &srsIn{
		Description: DescSingboxSRSIn,
	})
}

func IsSRSBytes(raw []byte) bool {
	return len(raw) >= 4 && raw[0] == srs.MagicBytes[0] && raw[1] == srs.MagicBytes[1] && raw[2] == srs.MagicBytes[2]
}

func ParseSRSBytes(raw []byte, entry *lib.Entry, wantDomain, wantAdGuard, wantIP bool) error {
	compat, err := srs.Read(bytes.NewReader(raw), true)
	if err != nil {
		return err
	}
	return collectHeadlessRules(compat.Options.Rules, entry, wantDomain, wantAdGuard, wantIP)
}

func collectHeadlessRules(rules []option.HeadlessRule, entry *lib.Entry, wantDomain, wantAdGuard, wantIP bool) error {
	for _, r := range rules {
		switch r.Type {
		case "", constant.RuleTypeDefault:
			d := r.DefaultOptions
			if wantDomain {
				for _, v := range d.Domain {
					entry.AddDomainRule(lib.DomainRule{Type: lib.RuleTypeDomain, Value: v})
				}
				for _, v := range d.DomainSuffix {
					entry.AddDomainRule(lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: strings.TrimPrefix(v, ".")})
				}
				for _, v := range d.DomainKeyword {
					entry.AddDomainRule(lib.DomainRule{Type: lib.RuleTypeDomainKeyword, Value: v})
				}
				for _, v := range d.DomainRegex {
					entry.AddDomainRule(lib.DomainRule{Type: lib.RuleTypeDomainRegex, Value: v})
				}
			}
			if wantAdGuard {
				for _, v := range d.AdGuardDomain {
					entry.AddAdGuardRule(v)
				}
			}
			if wantIP {
				for _, cidr := range d.IPCIDR {
					if err := entry.AddPrefix(cidr); err != nil {
						return err
					}
				}
			}
		case constant.RuleTypeLogical:
			if err := collectHeadlessRules(r.LogicalOptions.Rules, entry, wantDomain, wantAdGuard, wantIP); err != nil {
				return err
			}
		}
	}
	return nil
}

type srsIn struct {
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
	Kind        lib.EntryKind
	OnlyIPType  lib.IPType
	S3Endpoint  string
	S3Region    string
	S3Bucket    string
}

func NewSRSInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name        string        `json:"name"`
		Names       []string      `json:"names"`
		URI         string        `json:"uri"`
		FallbackURI string        `json:"fallbackURI"`
		InputDir    string        `json:"inputDir"`
		FallbackDir string        `json:"fallbackDir"`
		Optional    bool          `json:"optional"`
		Want        []string      `json:"wantedList"`
		Exclude     []string      `json:"excludedList"`
		Kind        lib.EntryKind `json:"kind"`
		OnlyIPType  lib.IPType    `json:"onlyIPType"`
		S3Endpoint  string        `json:"s3Endpoint"`
		S3Region    string        `json:"s3Region"`
		S3Bucket    string        `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSingboxSRSIn, action, err)
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

	s := &srsIn{
		Type:        TypeSingboxSRSIn,
		Action:      action,
		Description: DescSingboxSRSIn,
		Names:       names,
		URI:         strings.TrimSpace(tmp.URI),
		FallbackURI: strings.TrimSpace(tmp.FallbackURI),
		InputDir:    strings.TrimSpace(tmp.InputDir),
		FallbackDir: strings.TrimSpace(tmp.FallbackDir),
		Optional:    tmp.Optional,
		Want:        toUpperSet(tmp.Want),
		Exclude:     toUpperSet(tmp.Exclude),
		Kind:        lib.EntryKind(strings.ToLower(strings.TrimSpace(string(tmp.Kind)))),
		OnlyIPType:  tmp.OnlyIPType,
		S3Endpoint:  strings.TrimSpace(tmp.S3Endpoint),
		S3Region:    strings.TrimSpace(tmp.S3Region),
		S3Bucket:    strings.TrimSpace(tmp.S3Bucket),
	}

	if s.InputDir == "" {
		if len(s.Names) == 0 || s.URI == "" {
			return nil, fmt.Errorf("[type %s | action %s] missing inputDir or (name/names and uri)", s.Type, s.Action)
		}
	} else if len(s.Names) > 0 || s.URI != "" {
		return nil, fmt.Errorf("[type %s | action %s] inputDir cannot be used with name or uri", s.Type, s.Action)
	}

	return s, nil
}

func (s *srsIn) GetType() string {
	return s.Type
}

func (s *srsIn) GetAction() lib.Action {
	return s.Action
}

func (s *srsIn) GetDescription() string {
	return s.Description
}

func (s *srsIn) wantKinds() (bool, bool, bool) {
	switch s.Kind {
	case lib.EntryKindDomain:
		return true, false, false
	case lib.EntryKindAdGuard:
		return false, true, false
	case lib.EntryKindIP:
		return false, false, true
	default:
		return true, true, true
	}
}

func (s *srsIn) Input(container lib.Container) (lib.Container, error) {
	if s.InputDir != "" {
		return s.inputFromDir(container)
	}

	raw, err := s.readURIWithFallback()
	if err != nil {
		if s.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	for _, name := range s.Names {
		if err := s.applyBytes(container, name, raw); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
		}
	}
	return container, nil
}

func (s *srsIn) readURIWithFallback() ([]byte, error) {
	content, err := s.readURI(s.URI)
	if err != nil && s.FallbackURI != "" {
		return s.readURI(s.FallbackURI)
	}
	return content, err
}

func (s *srsIn) readURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: s.S3Endpoint,
			Region:   s.S3Region,
			Bucket:   s.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (s *srsIn) inputFromDir(container lib.Container) (lib.Container, error) {
	if lib.IsS3URI(s.InputDir) {
		err := s.inputFromS3Dir(container)
		if err == nil {
			return container, nil
		}
		if s.FallbackDir != "" {
			if fbErr := s.inputFromLocalDir(s.FallbackDir, container); fbErr != nil {
				if s.Optional {
					return container, nil
				}
				return nil, fmt.Errorf("[type %s | action %s] s3 failed (%v) and fallbackDir failed: %w", s.Type, s.Action, err, fbErr)
			}
			return container, nil
		}
		if s.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	if err := s.inputFromLocalDir(s.InputDir, container); err != nil {
		if s.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}
	return container, nil
}

func (s *srsIn) inputFromS3Dir(container lib.Container) error {
	bucket, prefix, err := lib.ParseS3URI(s.InputDir)
	if err != nil {
		return err
	}
	cfg := lib.S3Config{
		Endpoint: s.S3Endpoint,
		Region:   s.S3Region,
		Bucket:   s.S3Bucket,
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
		if !strings.EqualFold(path.Ext(base), ".srs") {
			continue
		}
		name := strings.TrimSuffix(base, path.Ext(base))
		if !s.shouldLoad(name) {
			continue
		}
		raw, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		if err := s.applyBytes(container, name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *srsIn) inputFromLocalDir(dir string, container lib.Container) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range dirEntries {
		if de.IsDir() || !strings.EqualFold(filepath.Ext(de.Name()), ".srs") {
			continue
		}
		name := strings.TrimSuffix(de.Name(), filepath.Ext(de.Name()))
		if !s.shouldLoad(name) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			return err
		}
		if err := s.applyBytes(container, name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *srsIn) shouldLoad(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	if len(s.Want) > 0 && !s.Want[upper] {
		return false
	}
	if s.Exclude[upper] {
		return false
	}
	return true
}

func (s *srsIn) applyBytes(container lib.Container, name string, raw []byte) error {
	entry := lib.NewEntry(name)
	wantDomain, wantAdGuard, wantIP := s.wantKinds()
	if err := ParseSRSBytes(raw, entry, wantDomain, wantAdGuard, wantIP); err != nil {
		return err
	}
	ignoreIP := lib.GetIgnoreIPType(s.OnlyIPType)
	switch s.Action {
	case lib.ActionAdd:
		return container.Add(entry, ignoreIP)
	case lib.ActionReplace:
		return container.Replace(entry, s.Kind, ignoreIP)
	case lib.ActionRemove:
		return container.Remove(entry, lib.CaseRemoveRule, s.Kind, ignoreIP)
	default:
		return fmt.Errorf("unsupported action %s", s.Action)
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
