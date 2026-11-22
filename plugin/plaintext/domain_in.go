package plaintext

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
	"github.com/Yuu518/sing-box-rules/plugin/v2fly"
)

const (
	TypeTextDomainIn = "textDomain"
	DescTextDomainIn = "Load domain rules from plain text file, URL, S3/R2, directory, or inline list"
)

func init() {
	lib.RegisterInputConfigCreator(TypeTextDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewDomainTextInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeTextDomainIn, &domainTextIn{
		Description: DescTextDomainIn,
	})
}

type domainTextIn struct {
	Type                 string
	Action               lib.Action
	Description          string
	Name                 string
	Names                []string
	URI                  string
	FallbackURI          string
	InputDir             string
	FallbackDir          string
	Optional             bool
	Rules                []string
	Want                 map[string]bool
	Exclude              map[string]bool
	SkipLines            int
	RemovePrefixesInLine []string
	RemoveSuffixesInLine []string
	ExcludeAttrs         map[string]bool
	OnlyRuleTypes        map[lib.RuleType]bool
	ValidDomainOnly      bool
	S3Endpoint           string
	S3Region             string
	S3Bucket             string
}

func NewDomainTextInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name                 string   `json:"name"`
		Names                []string `json:"names"`
		URI                  string   `json:"uri"`
		FallbackURI          string   `json:"fallbackURI"`
		InputDir             string   `json:"inputDir"`
		FallbackDir          string   `json:"fallbackDir"`
		Optional             bool     `json:"optional"`
		Rules                []string `json:"rules"`
		Want                 []string `json:"wantedList"`
		Exclude              []string `json:"excludedList"`
		SkipLines            int      `json:"skipLines"`
		RemovePrefixesInLine []string `json:"removePrefixesInLine"`
		RemoveSuffixesInLine []string `json:"removeSuffixesInLine"`
		ExcludeAttrs         []string `json:"excludeAttrs"`
		OnlyRuleTypes        []string `json:"onlyRuleTypes"`
		ValidDomainOnly      bool     `json:"validDomainOnly"`
		S3Endpoint           string   `json:"s3Endpoint"`
		S3Region             string   `json:"s3Region"`
		S3Bucket             string   `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeTextDomainIn, action, err)
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

	d := &domainTextIn{
		Type:                 TypeTextDomainIn,
		Action:               action,
		Description:          DescTextDomainIn,
		Name:                 strings.TrimSpace(tmp.Name),
		Names:                names,
		URI:                  strings.TrimSpace(tmp.URI),
		FallbackURI:          strings.TrimSpace(tmp.FallbackURI),
		InputDir:             strings.TrimSpace(tmp.InputDir),
		FallbackDir:          strings.TrimSpace(tmp.FallbackDir),
		Optional:             tmp.Optional,
		Rules:                tmp.Rules,
		Want:                 toUpperMap(tmp.Want),
		Exclude:              toUpperMap(tmp.Exclude),
		SkipLines:            tmp.SkipLines,
		RemovePrefixesInLine: tmp.RemovePrefixesInLine,
		RemoveSuffixesInLine: tmp.RemoveSuffixesInLine,
		ExcludeAttrs:         toLowerAttrMap(tmp.ExcludeAttrs),
		OnlyRuleTypes:        toRuleTypeMap(tmp.OnlyRuleTypes),
		ValidDomainOnly:      tmp.ValidDomainOnly,
		S3Endpoint:           strings.TrimSpace(tmp.S3Endpoint),
		S3Region:             strings.TrimSpace(tmp.S3Region),
		S3Bucket:             strings.TrimSpace(tmp.S3Bucket),
	}

	if d.InputDir == "" {
		if len(d.Names) == 0 {
			return nil, fmt.Errorf("[type %s | action %s] missing name/names or inputDir", d.Type, d.Action)
		}
		if d.URI == "" && len(d.Rules) == 0 {
			return nil, fmt.Errorf("[type %s | action %s] missing uri or rules", d.Type, d.Action)
		}
	} else if len(d.Names) > 0 || d.URI != "" || len(d.Rules) > 0 {
		return nil, fmt.Errorf("[type %s | action %s] inputDir cannot be used with name, uri, or rules", d.Type, d.Action)
	}

	return d, nil
}

func (d *domainTextIn) GetType() string {
	return d.Type
}

func (d *domainTextIn) GetAction() lib.Action {
	return d.Action
}

func (d *domainTextIn) GetDescription() string {
	return d.Description
}

func (d *domainTextIn) Input(container lib.Container) (lib.Container, error) {
	if d.InputDir != "" {
		return d.inputFromDir(container)
	}

	var parsedLines []v2fly.ParsedLine
	if d.URI != "" {
		content, err := d.readURIWithFallback()
		if err != nil {
			if d.Optional {
				return container, nil
			}
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		lines, err := d.scanLines(bytes.NewReader(content))
		if err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		parsedLines = append(parsedLines, lines...)
	}

	for _, r := range d.Rules {
		if parsed, ok := d.parseLine(r); ok {
			parsedLines = append(parsedLines, parsed)
		}
	}

	for _, name := range d.Names {
		if err := d.applyParsed(container, name, parsedLines); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
	}

	return container, nil
}

func (d *domainTextIn) readURIWithFallback() ([]byte, error) {
	content, err := d.readURI(d.URI)
	if err != nil && d.FallbackURI != "" {
		return d.readURI(d.FallbackURI)
	}
	return content, err
}

func (d *domainTextIn) readURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: d.S3Endpoint,
			Region:   d.S3Region,
			Bucket:   d.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (d *domainTextIn) inputFromDir(container lib.Container) (lib.Container, error) {
	if lib.IsS3URI(d.InputDir) {
		err := d.inputFromS3Dir(container)
		if err == nil {
			return container, nil
		}
		if d.FallbackDir != "" {
			if fbErr := d.inputFromLocalDir(d.FallbackDir, container); fbErr != nil {
				if d.Optional {
					return container, nil
				}
				return nil, fmt.Errorf("[type %s | action %s] s3 failed (%v) and fallbackDir failed: %w", d.Type, d.Action, err, fbErr)
			}
			return container, nil
		}
		if d.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
	}

	if err := d.inputFromLocalDir(d.InputDir, container); err != nil {
		if d.Optional {
			return container, nil
		}
		return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
	}
	return container, nil
}

func (d *domainTextIn) inputFromS3Dir(container lib.Container) error {
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
		name := strings.TrimSuffix(path.Base(key), path.Ext(path.Base(key)))
		if !d.shouldLoad(name) {
			continue
		}
		content, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		lines, err := d.scanLines(bytes.NewReader(content))
		if err != nil {
			return err
		}
		if err := d.applyParsed(container, name, lines); err != nil {
			return err
		}
	}
	return nil
}

func (d *domainTextIn) inputFromLocalDir(dir string, container lib.Container) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range entries {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		name := strings.TrimSuffix(de.Name(), filepath.Ext(de.Name()))
		if !d.shouldLoad(name) {
			continue
		}
		f, err := os.Open(filepath.Join(dir, de.Name()))
		if err != nil {
			return err
		}
		lines, scanErr := d.scanLines(f)
		f.Close()
		if scanErr != nil {
			return scanErr
		}
		if err := d.applyParsed(container, name, lines); err != nil {
			return err
		}
	}
	return nil
}

func (d *domainTextIn) shouldLoad(name string) bool {
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

func (d *domainTextIn) scanLines(r io.Reader) ([]v2fly.ParsedLine, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []v2fly.ParsedLine
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= d.SkipLines {
			continue
		}
		if parsed, ok := d.parseLine(scanner.Text()); ok {
			out = append(out, parsed)
		}
	}
	return out, scanner.Err()
}

func (d *domainTextIn) parseLine(raw string) (v2fly.ParsedLine, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return v2fly.ParsedLine{}, false
	}
	for _, prefix := range d.RemovePrefixesInLine {
		line = strings.TrimPrefix(line, prefix)
	}
	for _, suffix := range d.RemoveSuffixesInLine {
		line = strings.TrimSuffix(line, suffix)
	}
	parsed, ok := v2fly.ParseV2FlyLine(line)
	if !ok {
		return v2fly.ParsedLine{}, false
	}
	if parsed.IsInclude {
		return parsed, true
	}
	if len(d.ExcludeAttrs) > 0 {
		for _, a := range parsed.Rule.Attrs {
			if d.ExcludeAttrs[strings.ToLower(strings.TrimPrefix(a, "@"))] {
				return v2fly.ParsedLine{}, false
			}
		}
	}
	if len(d.OnlyRuleTypes) > 0 && !d.OnlyRuleTypes[parsed.Rule.Type] {
		return v2fly.ParsedLine{}, false
	}
	if d.ValidDomainOnly && (parsed.Rule.Type == lib.RuleTypeDomain || parsed.Rule.Type == lib.RuleTypeDomainSuffix) {
		if !lib.IsValidDomainOrTLD(parsed.Rule.Value) {
			return v2fly.ParsedLine{}, false
		}
	}
	return parsed, true
}

func (d *domainTextIn) applyParsed(container lib.Container, name string, parsedLines []v2fly.ParsedLine) error {
	switch d.Action {
	case lib.ActionAdd:
		entry := lib.NewEntry(name)
		for _, p := range parsedLines {
			if p.IsInclude {
				entry.AddInclude(p.Include)
			} else {
				entry.AddDomainRule(p.Rule)
			}
		}
		return container.Add(entry)

	case lib.ActionReplace:
		entry := lib.NewEntry(name)
		for _, p := range parsedLines {
			if p.IsInclude {
				entry.AddInclude(p.Include)
			} else {
				entry.AddDomainRule(p.Rule)
			}
		}
		return container.Replace(entry, lib.EntryKindDomain)

	case lib.ActionRemove:
		target, found := container.GetEntry(name)
		if !found {
			return nil
		}
		for _, p := range parsedLines {
			if p.IsInclude {
				continue
			}
			if p.ExplicitTyp {
				target.RemoveDomainRule(p.Rule.Type, p.Rule.Value)
			} else {
				target.RemoveDomainValueAllTypes(p.Rule.Value)
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported action %s", d.Action)
	}
}

func toUpperMap(items []string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range items {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			m[item] = true
		}
	}
	return m
}

func toLowerAttrMap(items []string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range items {
		if item = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(item, "@"))); item != "" {
			m[item] = true
		}
	}
	return m
}

func toRuleTypeMap(items []string) map[lib.RuleType]bool {
	m := make(map[lib.RuleType]bool)
	for _, item := range items {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			m[lib.RuleType(item)] = true
		}
	}
	return m
}
