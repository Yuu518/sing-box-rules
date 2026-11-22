package v2fly

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
)

const (
	TypeV2FlyDomainIn = "v2flyDomain"
	DescV2FlyDomainIn = "Load v2fly domain-list-community format rules from local directory, file, HTTP(S) URL, or S3/R2"
)

func init() {
	lib.RegisterInputConfigCreator(TypeV2FlyDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewDLCInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeV2FlyDomainIn, &dlcIn{
		Description: DescV2FlyDomainIn,
	})
}

type ParsedLine struct {
	IsInclude   bool
	Include     lib.IncludeRef
	Rule        lib.DomainRule
	ExplicitTyp bool
}

func ParseV2FlyLine(raw string) (ParsedLine, bool) {
	line, _, _ := strings.Cut(raw, "#")
	line = strings.TrimSpace(line)
	if line == "" {
		return ParsedLine{}, false
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ParsedLine{}, false
	}

	token := fields[0]
	var attrs []string
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "@") {
			attrs = append(attrs, strings.TrimPrefix(f, "@"))
		}
	}

	if strings.HasPrefix(token, "include:") {
		target := strings.TrimSpace(strings.TrimPrefix(token, "include:"))
		if target == "" {
			return ParsedLine{}, false
		}
		ref := lib.IncludeRef{Target: strings.ToUpper(target)}
		if idx := strings.Index(target, "@"); idx >= 0 {
			ref.Target = strings.ToUpper(strings.TrimSpace(target[:idx]))
			attr := strings.TrimSpace(target[idx+1:])
			if strings.HasPrefix(attr, "-") || strings.HasPrefix(attr, "!") {
				ref.Negate = true
				ref.Attr = strings.ToLower(strings.TrimLeft(attr, "-!"))
			} else {
				ref.Attr = strings.ToLower(attr)
			}
		} else if len(attrs) > 0 {
			attr := attrs[0]
			if strings.HasPrefix(attr, "-") || strings.HasPrefix(attr, "!") {
				ref.Negate = true
				ref.Attr = strings.ToLower(strings.TrimLeft(attr, "-!"))
			} else {
				ref.Attr = strings.ToLower(attr)
			}
		}
		if ref.Target == "" {
			return ParsedLine{}, false
		}
		return ParsedLine{
			IsInclude: true,
			Include:   ref,
		}, true
	}

	ruleType := lib.RuleTypeDomainSuffix
	explicit := false
	value := token

	switch {
	case strings.HasPrefix(token, "full:"):
		ruleType = lib.RuleTypeDomain
		value = strings.TrimPrefix(token, "full:")
		explicit = true
	case strings.HasPrefix(token, "domain:"):
		ruleType = lib.RuleTypeDomainSuffix
		value = strings.TrimPrefix(token, "domain:")
		explicit = true
	case strings.HasPrefix(token, "keyword:"):
		ruleType = lib.RuleTypeDomainKeyword
		value = strings.TrimPrefix(token, "keyword:")
		explicit = true
	case strings.HasPrefix(token, "regexp:"):
		ruleType = lib.RuleTypeDomainRegex
		value = strings.TrimPrefix(token, "regexp:")
		explicit = true
	}

	if ruleType != lib.RuleTypeDomainRegex {
		if idx := strings.Index(value, ":@"); idx >= 0 {
			attrPart := value[idx+2:]
			value = value[:idx]
			for _, part := range strings.Split(attrPart, ":@") {
				part = strings.TrimSpace(strings.TrimPrefix(part, "@"))
				if part != "" {
					attrs = append(attrs, part)
				}
			}
		}
	} else {
		if idx := strings.LastIndex(value, ":@"); idx >= 0 {
			attrPart := value[idx+2:]
			value = value[:idx]
			for _, part := range strings.Split(attrPart, ":@") {
				part = strings.TrimSpace(strings.TrimPrefix(part, "@"))
				if part != "" {
					attrs = append(attrs, part)
				}
			}
		}
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return ParsedLine{}, false
	}

	return ParsedLine{
		Rule: lib.DomainRule{
			Type:  ruleType,
			Value: value,
			Attrs: attrs,
		},
		ExplicitTyp: explicit,
	}, true
}

type dlcIn struct {
	Type          string
	Action        lib.Action
	Description   string
	Name          string
	URI           string
	InputDir      string
	FallbackDir   string
	Optional      bool
	Want          map[string]bool
	Exclude       map[string]bool
	ExcludeAttrs  map[string]bool
	OnlyRuleTypes map[lib.RuleType]bool
	S3Endpoint    string
	S3Region      string
	S3Bucket      string
}

func NewDLCInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name          string   `json:"name"`
		URI           string   `json:"uri"`
		InputDir      string   `json:"inputDir"`
		FallbackDir   string   `json:"fallbackDir"`
		Optional      bool     `json:"optional"`
		Want          []string `json:"wantedList"`
		Exclude       []string `json:"excludedList"`
		ExcludeAttrs  []string `json:"excludeAttrs"`
		OnlyRuleTypes []string `json:"onlyRuleTypes"`
		S3Endpoint    string   `json:"s3Endpoint"`
		S3Region      string   `json:"s3Region"`
		S3Bucket      string   `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeV2FlyDomainIn, action, err)
		}
	}

	d := &dlcIn{
		Type:          TypeV2FlyDomainIn,
		Action:        action,
		Description:   DescV2FlyDomainIn,
		Name:          strings.TrimSpace(tmp.Name),
		URI:           strings.TrimSpace(tmp.URI),
		InputDir:      strings.TrimSpace(tmp.InputDir),
		FallbackDir:   strings.TrimSpace(tmp.FallbackDir),
		Optional:      tmp.Optional,
		Want:          toUpperSet(tmp.Want),
		Exclude:       toUpperSet(tmp.Exclude),
		ExcludeAttrs:  toLowerSet(tmp.ExcludeAttrs),
		OnlyRuleTypes: toRuleTypeSet(tmp.OnlyRuleTypes),
		S3Endpoint:    strings.TrimSpace(tmp.S3Endpoint),
		S3Region:      strings.TrimSpace(tmp.S3Region),
		S3Bucket:      strings.TrimSpace(tmp.S3Bucket),
	}

	if d.InputDir == "" && d.URI == "" {
		return nil, fmt.Errorf("[type %s | action %s] missing inputDir or uri", d.Type, d.Action)
	}
	if d.InputDir != "" && (d.URI != "" || d.Name != "") {
		return nil, fmt.Errorf("[type %s | action %s] inputDir cannot be used with uri or name", d.Type, d.Action)
	}
	if d.URI != "" && d.Name == "" {
		return nil, fmt.Errorf("[type %s | action %s] missing name for uri", d.Type, d.Action)
	}

	return d, nil
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

func toLowerSet(items []string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range items {
		if item = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(item, "@"))); item != "" {
			m[item] = true
		}
	}
	return m
}

func toRuleTypeSet(items []string) map[lib.RuleType]bool {
	m := make(map[lib.RuleType]bool)
	for _, item := range items {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			m[lib.RuleType(item)] = true
		}
	}
	return m
}

func (d *dlcIn) GetType() string {
	return d.Type
}

func (d *dlcIn) GetAction() lib.Action {
	return d.Action
}

func (d *dlcIn) GetDescription() string {
	return d.Description
}

func (d *dlcIn) Input(container lib.Container) (lib.Container, error) {
	entries := make(map[string]*lib.Entry)

	switch {
	case d.URI != "":
		content, err := d.readSingleURI(d.URI)
		if err != nil {
			if d.Optional {
				return container, nil
			}
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		entry := lib.NewEntry(d.Name)
		if err := d.scanReader(bytes.NewReader(content), entry); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		entries[entry.GetName()] = entry

	case lib.IsS3URI(d.InputDir):
		if err := d.readS3Dir(entries); err != nil {
			if d.FallbackDir != "" {
				if fbErr := d.readLocalDir(d.FallbackDir, entries); fbErr != nil {
					if d.Optional {
						return container, nil
					}
					return nil, fmt.Errorf("[type %s | action %s] s3 failed (%v) and fallbackDir failed: %w", d.Type, d.Action, err, fbErr)
				}
			} else if d.Optional {
				return container, nil
			} else {
				return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
			}
		}

	default:
		if err := d.readLocalDir(d.InputDir, entries); err != nil {
			if d.Optional {
				return container, nil
			}
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
	}

	for _, entry := range entries {
		switch d.Action {
		case lib.ActionAdd:
			if err := container.Add(entry); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
			}
		case lib.ActionReplace:
			if err := container.Replace(entry, lib.EntryKindDomain); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindDomain); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
			}
		default:
			return nil, fmt.Errorf("[type %s | action %s] unsupported action", d.Type, d.Action)
		}
	}

	return container, nil
}

func (d *dlcIn) readSingleURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: d.S3Endpoint,
			Region:   d.S3Region,
			Bucket:   d.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (d *dlcIn) shouldLoadName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	if len(d.Want) > 0 && !d.Want[upper] {
		return false
	}
	if d.Exclude[upper] {
		return false
	}
	return true
}

func (d *dlcIn) readS3Dir(entries map[string]*lib.Entry) error {
	bucket, prefix, err := lib.ParseS3URI(d.InputDir)
	if err != nil {
		return err
	}
	cfg := lib.S3Config{
		Endpoint: d.S3Endpoint,
		Region:   d.S3Region,
		Bucket:   d.S3Bucket,
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
		name := path.Base(key)
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !d.shouldLoadName(name) {
			continue
		}
		content, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		entry := lib.NewEntry(name)
		if err := d.scanReader(bytes.NewReader(content), entry); err != nil {
			return fmt.Errorf("file %s: %w", key, err)
		}
		entries[entry.GetName()] = entry
	}
	return nil
}

func (d *dlcIn) readLocalDir(dir string, entries map[string]*lib.Entry) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !d.shouldLoadName(name) {
			continue
		}
		fullPath := filepath.Join(dir, name)
		f, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		entry := lib.NewEntry(name)
		scanErr := d.scanReader(f, entry)
		f.Close()
		if scanErr != nil {
			return fmt.Errorf("file %s: %w", fullPath, scanErr)
		}
		entries[entry.GetName()] = entry
	}
	return nil
}

func (d *dlcIn) scanReader(r io.Reader, entry *lib.Entry) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		parsed, ok := ParseV2FlyLine(scanner.Text())
		if !ok {
			continue
		}
		if parsed.IsInclude {
			entry.AddInclude(parsed.Include)
			continue
		}
		if d.shouldExcludeByAttr(parsed.Rule.Attrs) {
			continue
		}
		if len(d.OnlyRuleTypes) > 0 && !d.OnlyRuleTypes[parsed.Rule.Type] {
			continue
		}
		entry.AddDomainRule(parsed.Rule)
	}
	return scanner.Err()
}

func (d *dlcIn) shouldExcludeByAttr(attrs []string) bool {
	if len(d.ExcludeAttrs) == 0 {
		return false
	}
	for _, a := range attrs {
		if d.ExcludeAttrs[strings.ToLower(strings.TrimPrefix(a, "@"))] {
			return true
		}
	}
	return false
}
