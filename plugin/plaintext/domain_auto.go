package plaintext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/Yuu518/sing-box-rules/plugin/mihomo"
	"github.com/Yuu518/sing-box-rules/plugin/singbox"
	"github.com/Yuu518/sing-box-rules/plugin/v2fly"
	P "github.com/metacubex/mihomo/constant/provider"
)

const (
	TypeDomainAutoIn = "domain"
	DescDomainAutoIn = "Auto-detect and load domain rules from any format (v2fly, dnsmasq, GFWList, Surge, Clash YAML, sing-box JSON/SRS, mihomo MRS, Hosts, Adblock)"
)

func init() {
	lib.RegisterInputConfigCreator(TypeDomainAutoIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewDomainAutoInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeDomainAutoIn, &domainAutoIn{
		Description: DescDomainAutoIn,
	})
}

type domainAutoIn struct {
	Type            string
	Action          lib.Action
	Description     string
	Names           []string
	URI             string
	FallbackURI     string
	InputDir        string
	FallbackDir     string
	Optional        bool
	Rules           []string
	Want            map[string]bool
	Exclude         map[string]bool
	SkipLines       int
	SkipEntries     int
	ExcludeAttrs    map[string]bool
	OnlyRuleTypes   map[lib.RuleType]bool
	ValidDomainOnly bool
	S3Endpoint      string
	S3Region        string
	S3Bucket        string
}

func NewDomainAutoInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name            string   `json:"name"`
		Names           []string `json:"names"`
		URI             string   `json:"uri"`
		FallbackURI     string   `json:"fallbackURI"`
		InputDir        string   `json:"inputDir"`
		FallbackDir     string   `json:"fallbackDir"`
		Optional        bool     `json:"optional"`
		Rules           []string `json:"rules"`
		Want            []string `json:"wantedList"`
		Exclude         []string `json:"excludedList"`
		SkipLines       int      `json:"skipLines"`
		SkipEntries     int      `json:"skipEntries"`
		ExcludeAttrs    []string `json:"excludeAttrs"`
		OnlyRuleTypes   []string `json:"onlyRuleTypes"`
		ValidDomainOnly bool     `json:"validDomainOnly"`
		S3Endpoint      string   `json:"s3Endpoint"`
		S3Region        string   `json:"s3Region"`
		S3Bucket        string   `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeDomainAutoIn, action, err)
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

	d := &domainAutoIn{
		Type:            TypeDomainAutoIn,
		Action:          action,
		Description:     DescDomainAutoIn,
		Names:           names,
		URI:             strings.TrimSpace(tmp.URI),
		FallbackURI:     strings.TrimSpace(tmp.FallbackURI),
		InputDir:        strings.TrimSpace(tmp.InputDir),
		FallbackDir:     strings.TrimSpace(tmp.FallbackDir),
		Optional:        tmp.Optional,
		Rules:           tmp.Rules,
		Want:            toUpperMap(tmp.Want),
		Exclude:         toUpperMap(tmp.Exclude),
		SkipLines:       tmp.SkipLines,
		SkipEntries:     tmp.SkipEntries,
		ExcludeAttrs:    toLowerAttrMap(tmp.ExcludeAttrs),
		OnlyRuleTypes:   toRuleTypeMap(tmp.OnlyRuleTypes),
		ValidDomainOnly: tmp.ValidDomainOnly,
		S3Endpoint:      strings.TrimSpace(tmp.S3Endpoint),
		S3Region:        strings.TrimSpace(tmp.S3Region),
		S3Bucket:        strings.TrimSpace(tmp.S3Bucket),
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

func (d *domainAutoIn) GetType() string {
	return d.Type
}

func (d *domainAutoIn) GetAction() lib.Action {
	return d.Action
}

func (d *domainAutoIn) GetDescription() string {
	return d.Description
}

func (d *domainAutoIn) Input(container lib.Container) (lib.Container, error) {
	if d.InputDir != "" {
		return d.inputFromDir(container)
	}

	var parsed []v2fly.ParsedLine
	if d.URI != "" {
		content, err := d.readURIWithFallback()
		if err != nil {
			if d.Optional {
				return container, nil
			}
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		items, err := d.parseContent(content)
		if err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
		parsed = append(parsed, items...)
	}

	for _, r := range d.Rules {
		for _, item := range parseAnyDomainLine(r, false) {
			if d.acceptParsed(item) {
				parsed = append(parsed, item)
			}
		}
	}

	for _, name := range d.Names {
		if err := d.applyParsed(container, name, parsed); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
		}
	}

	return container, nil
}

func (d *domainAutoIn) readURIWithFallback() ([]byte, error) {
	content, err := d.readURI(d.URI)
	if err != nil && d.FallbackURI != "" {
		return d.readURI(d.FallbackURI)
	}
	return content, err
}

func (d *domainAutoIn) readURI(uri string) ([]byte, error) {
	if lib.IsS3URI(uri) {
		return lib.ReadS3Object(uri, lib.S3Config{
			Endpoint: d.S3Endpoint,
			Region:   d.S3Region,
			Bucket:   d.S3Bucket,
		})
	}
	return lib.ReadURIContent(uri)
}

func (d *domainAutoIn) inputFromDir(container lib.Container) (lib.Container, error) {
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

func (d *domainAutoIn) inputFromS3Dir(container lib.Container) error {
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
		base := path.Base(key)
		if strings.HasPrefix(base, ".") {
			continue
		}
		name := strings.TrimSuffix(base, path.Ext(base))
		if !d.shouldLoad(name) {
			continue
		}
		content, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		items, err := d.parseContent(content)
		if err != nil {
			return err
		}
		if err := d.applyParsed(container, name, items); err != nil {
			return err
		}
	}
	return nil
}

func (d *domainAutoIn) inputFromLocalDir(dir string, container lib.Container) error {
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
		content, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			return err
		}
		items, err := d.parseContent(content)
		if err != nil {
			return err
		}
		if err := d.applyParsed(container, name, items); err != nil {
			return err
		}
	}
	return nil
}

func (d *domainAutoIn) shouldLoad(name string) bool {
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

func (d *domainAutoIn) parseContent(raw []byte) ([]v2fly.ParsedLine, error) {
	if singbox.IsSRSBytes(raw) {
		tmp := lib.NewEntry("_")
		if err := singbox.ParseSRSBytes(raw, tmp, true, false, false); err != nil {
			return nil, err
		}
		rules := tmp.GetDomainRules()
		items := make([]v2fly.ParsedLine, 0, len(rules))
		for _, r := range rules {
			items = append(items, v2fly.ParsedLine{Rule: r, ExplicitTyp: true})
		}
		return d.filterParsed(items), nil
	}

	if behavior, ok := mihomo.IsMRSBytes(raw); ok {
		if behavior != P.Domain {
			return nil, nil
		}
		tmp := lib.NewEntry("_")
		if _, err := mihomo.ParseMRSBytes(raw, tmp, true, false); err != nil {
			return nil, err
		}
		rules := tmp.GetDomainRules()
		items := make([]v2fly.ParsedLine, 0, len(rules))
		for _, r := range rules {
			items = append(items, v2fly.ParsedLine{Rule: r, ExplicitTyp: true})
		}
		return d.filterParsed(items), nil
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if items, ok := tryParseSingboxJSON(trimmed); ok {
		return d.filterParsed(items), nil
	}

	if isGFWListPayload(trimmed) {
		decoded := decodeGFWList(trimmed)
		domains := extractGFWListDomains(decoded)
		items := make([]v2fly.ParsedLine, 0, len(domains))
		for _, dom := range domains {
			items = append(items, v2fly.ParsedLine{
				Rule: lib.DomainRule{
					Type:  lib.RuleTypeDomainSuffix,
					Value: dom,
				},
			})
		}
		return d.filterParsed(items), nil
	}

	var out []v2fly.ParsedLine
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	entryNo := 0
	inYAMLPayload := false

	for scanner.Scan() {
		lineNo++
		if lineNo <= d.SkipLines {
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "payload:" {
			inYAMLPayload = true
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		items := parseAnyDomainLine(line, inYAMLPayload)
		if len(items) == 0 {
			continue
		}
		entryNo++
		if entryNo <= d.SkipEntries {
			continue
		}
		for _, item := range items {
			if d.acceptParsed(item) {
				out = append(out, item)
			}
		}
	}

	return out, scanner.Err()
}

func (d *domainAutoIn) filterParsed(items []v2fly.ParsedLine) []v2fly.ParsedLine {
	out := make([]v2fly.ParsedLine, 0, len(items))
	for _, item := range items {
		if d.acceptParsed(item) {
			out = append(out, item)
		}
	}
	return out
}

func (d *domainAutoIn) acceptParsed(parsed v2fly.ParsedLine) bool {
	if parsed.IsInclude {
		return true
	}
	if len(d.ExcludeAttrs) > 0 {
		for _, a := range parsed.Rule.Attrs {
			if d.ExcludeAttrs[strings.ToLower(strings.TrimPrefix(a, "@"))] {
				return false
			}
		}
	}
	if len(d.OnlyRuleTypes) > 0 && !d.OnlyRuleTypes[parsed.Rule.Type] {
		return false
	}
	if d.ValidDomainOnly && (parsed.Rule.Type == lib.RuleTypeDomain || parsed.Rule.Type == lib.RuleTypeDomainSuffix) {
		if !lib.IsValidDomainOrTLD(parsed.Rule.Value) {
			return false
		}
	}
	return true
}

func (d *domainAutoIn) applyParsed(container lib.Container, name string, parsedLines []v2fly.ParsedLine) error {
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

func tryParseSingboxJSON(data []byte) ([]v2fly.ParsedLine, bool) {
	if len(data) == 0 || data[0] != '{' {
		return nil, false
	}
	var doc struct {
		Rules []struct {
			Domain        []string `json:"domain"`
			DomainSuffix  []string `json:"domain_suffix"`
			DomainKeyword []string `json:"domain_keyword"`
			DomainRegex   []string `json:"domain_regex"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Rules) == 0 {
		return nil, false
	}
	var out []v2fly.ParsedLine
	for _, r := range doc.Rules {
		for _, v := range r.Domain {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				out = append(out, v2fly.ParsedLine{Rule: lib.DomainRule{Type: lib.RuleTypeDomain, Value: v}, ExplicitTyp: true})
			}
		}
		for _, v := range r.DomainSuffix {
			if v = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), ".")); v != "" {
				out = append(out, v2fly.ParsedLine{Rule: lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: v}, ExplicitTyp: true})
			}
		}
		for _, v := range r.DomainKeyword {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				out = append(out, v2fly.ParsedLine{Rule: lib.DomainRule{Type: lib.RuleTypeDomainKeyword, Value: v}, ExplicitTyp: true})
			}
		}
		for _, v := range r.DomainRegex {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v2fly.ParsedLine{Rule: lib.DomainRule{Type: lib.RuleTypeDomainRegex, Value: v}, ExplicitTyp: true})
			}
		}
	}
	return out, true
}

func isGFWListPayload(trimmed []byte) bool {
	if bytes.HasPrefix(trimmed, []byte("[AutoProxy")) {
		return true
	}
	if bytes.ContainsAny(trimmed, ":,./#") {
		return false
	}
	decoded := decodeGFWList(trimmed)
	return bytes.Contains(decoded, []byte("[AutoProxy"))
}

func parseAnyDomainLine(raw string, yamlPayload bool) []v2fly.ParsedLine {
	line := strings.TrimSpace(raw)
	if line == "" {
		return nil
	}

	fromYAMLItem := false
	if strings.HasPrefix(line, "- ") {
		fromYAMLItem = true
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if len(line) >= 2 && ((line[0] == '\'' && line[len(line)-1] == '\'') || (line[0] == '"' && line[len(line)-1] == '"')) {
			line = strings.TrimSpace(line[1 : len(line)-1])
		}
	}

	if !strings.HasPrefix(line, "regexp:") {
		line, _, _ = strings.Cut(line, "#")
		if !strings.Contains(line, "://") {
			line, _, _ = strings.Cut(line, "//")
		}
		line = strings.TrimSpace(line)
	}
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "@@") {
		return nil
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return nil
	}
	if isAdGuardNonRule(line) {
		return nil
	}

	if matches := dnsmasqAnyRegex.FindStringSubmatch(line); len(matches) >= 2 {
		dom := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(matches[1], ".")))
		if lib.IsValidDomainOrTLD(dom) {
			return []v2fly.ParsedLine{{
				Rule: lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: dom},
			}}
		}
		return nil
	}

	if strings.HasPrefix(line, "||") {
		dom := strings.TrimPrefix(line, "||")
		if idx := strings.IndexAny(dom, "^/$"); idx >= 0 {
			dom = dom[:idx]
		}
		dom = strings.ToLower(strings.Trim(dom, ". "))
		if lib.IsValidDomainOrTLD(dom) {
			return []v2fly.ParsedLine{{
				Rule: lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: dom},
			}}
		}
		return nil
	}

	if strings.Contains(line, ",") && !strings.HasPrefix(line, "regexp:") {
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			kind := strings.ToUpper(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])
			switch kind {
			case "DOMAIN", "HOST":
				if val != "" {
					return []v2fly.ParsedLine{{
						Rule:        lib.DomainRule{Type: lib.RuleTypeDomain, Value: strings.ToLower(val)},
						ExplicitTyp: true,
					}}
				}
				return nil
			case "DOMAIN-SUFFIX", "HOST-SUFFIX":
				val = strings.ToLower(strings.TrimPrefix(val, "."))
				if val != "" {
					return []v2fly.ParsedLine{{
						Rule:        lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val},
						ExplicitTyp: true,
					}}
				}
				return nil
			case "DOMAIN-KEYWORD", "HOST-KEYWORD":
				if val != "" {
					return []v2fly.ParsedLine{{
						Rule:        lib.DomainRule{Type: lib.RuleTypeDomainKeyword, Value: strings.ToLower(val)},
						ExplicitTyp: true,
					}}
				}
				return nil
			case "DOMAIN-REGEX":
				if val != "" {
					return []v2fly.ParsedLine{{
						Rule:        lib.DomainRule{Type: lib.RuleTypeDomainRegex, Value: val},
						ExplicitTyp: true,
					}}
				}
				return nil
			case "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "USER-AGENT", "PROCESS-NAME", "PROCESS-PATH", "URL-REGEX", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT", "NETWORK", "PROTOCOL", "RULE-SET", "AND", "OR", "NOT", "FINAL":
				return nil
			}
		}
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			var out []v2fly.ParsedLine
			for _, host := range fields[1:] {
				host = strings.ToLower(strings.TrimSpace(host))
				if isIgnoredHost(host) || !lib.IsValidDomainOrTLD(host) {
					continue
				}
				out = append(out, v2fly.ParsedLine{
					Rule: lib.DomainRule{Type: lib.RuleTypeDomain, Value: host},
				})
			}
			return out
		}
	}

	if strings.HasPrefix(line, "+.") || strings.HasPrefix(line, "*.") || strings.HasPrefix(line, ".") {
		val := strings.TrimPrefix(line, "+.")
		val = strings.TrimPrefix(val, "*.")
		val = strings.TrimPrefix(val, ".")
		val = strings.ToLower(strings.TrimSpace(val))
		if lib.IsValidDomainOrTLD(val) {
			return []v2fly.ParsedLine{{
				Rule: lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val},
			}}
		}
		return nil
	}

	if parsed, ok := v2fly.ParseV2FlyLine(line); ok {
		if parsed.IsInclude {
			return []v2fly.ParsedLine{parsed}
		}
		if !parsed.ExplicitTyp {
			if _, err := netip.ParseAddr(parsed.Rule.Value); err == nil {
				return nil
			}
			if _, err := netip.ParsePrefix(parsed.Rule.Value); err == nil {
				return nil
			}
			if (yamlPayload || fromYAMLItem) && lib.IsValidDomainOrTLD(parsed.Rule.Value) {
				parsed.Rule.Type = lib.RuleTypeDomain
			}
		}
		return []v2fly.ParsedLine{parsed}
	}

	return nil
}

func isIgnoredHost(host string) bool {
	switch host {
	case "", "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts":
		return true
	}
	return false
}
