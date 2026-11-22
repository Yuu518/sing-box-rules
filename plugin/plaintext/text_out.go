package plaintext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeTextDomainOut  = "textDomain"
	DescTextDomainOut  = "Convert domain rules to plain text files"
	TypeTextIPOut      = "textIP"
	DescTextIPOut      = "Convert IP/CIDR rules to plain text files"
	TypeTextAdGuardOut = "textAdGuard"
	DescTextAdGuardOut = "Convert AdGuard DNS filter rules to plain text files"
)

var (
	defaultTextSiteOutputDir    = filepath.Join("./", "rule-set", "text", "geosite")
	defaultTextIPOutputDir      = filepath.Join("./", "rule-set", "text", "geoip")
	defaultTextAdGuardOutputDir = filepath.Join("./", "publish")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeTextDomainOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewTextSiteOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeTextDomainOut, &textSiteOut{
		Description: DescTextDomainOut,
	})

	lib.RegisterOutputConfigCreator(TypeTextIPOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewTextIPOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeTextIPOut, &textIPOut{
		Description: DescTextIPOut,
	})

	lib.RegisterOutputConfigCreator(TypeTextAdGuardOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewTextAdGuardOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeTextAdGuardOut, &textAdGuardOut{
		Description: DescTextAdGuardOut,
	})
}

type textSiteOut struct {
	Type             string
	Action           lib.Action
	Description      string
	OutputDir        string
	OutputName       string
	OutputExt        string
	Want             []string
	Exclude          []string
	Format           string
	ExcludeRuleTypes map[lib.RuleType]bool
	AddPrefixInLine  string
	AddSuffixInLine  string
}

func NewTextSiteOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir        string   `json:"outputDir"`
		OutputName       string   `json:"outputName"`
		OutputExt        string   `json:"outputExtension"`
		Want             []string `json:"wantedList"`
		Exclude          []string `json:"excludedList"`
		Format           string   `json:"format"`
		ExcludeRuleTypes []string `json:"excludeRuleTypes"`
		AddPrefixInLine  string   `json:"addPrefixInLine"`
		AddSuffixInLine  string   `json:"addSuffixInLine"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeTextDomainOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultTextSiteOutputDir
	}
	outputExt := strings.TrimSpace(tmp.OutputExt)
	if outputExt == "" {
		outputExt = ".txt"
	}
	format := strings.ToLower(strings.TrimSpace(tmp.Format))
	if format == "" {
		format = "prefixed"
	}

	return &textSiteOut{
		Type:             TypeTextDomainOut,
		Action:           action,
		Description:      DescTextDomainOut,
		OutputDir:        outputDir,
		OutputName:       strings.TrimSpace(tmp.OutputName),
		OutputExt:        outputExt,
		Want:             tmp.Want,
		Exclude:          tmp.Exclude,
		Format:           format,
		ExcludeRuleTypes: toRuleTypeMap(tmp.ExcludeRuleTypes),
		AddPrefixInLine:  tmp.AddPrefixInLine,
		AddSuffixInLine:  tmp.AddSuffixInLine,
	}, nil
}

func (t *textSiteOut) GetType() string {
	return t.Type
}

func (t *textSiteOut) GetAction() lib.Action {
	return t.Action
}

func (t *textSiteOut) GetDescription() string {
	return t.Description
}

func (t *textSiteOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, t.Want, t.Exclude)
	if err := os.MkdirAll(t.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasDomainRules() {
			continue
		}

		lines := t.formatEntry(entry)
		if len(lines) == 0 && t.OutputName == "" {
			continue
		}

		var buf bytes.Buffer
		for _, line := range lines {
			if t.AddPrefixInLine != "" {
				buf.WriteString(t.AddPrefixInLine)
			}
			buf.WriteString(line)
			if t.AddSuffixInLine != "" {
				buf.WriteString(t.AddSuffixInLine)
			}
			buf.WriteByte('\n')
		}

		filename := entry.GetLowerName() + t.OutputExt
		if t.OutputName != "" && len(names) == 1 {
			filename = t.OutputName
		}

		if err := os.WriteFile(filepath.Join(t.OutputDir, filename), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
		log.Printf("[%s] %s --> %s", t.Type, filename, t.OutputDir)
	}

	return nil
}

func (t *textSiteOut) formatEntry(entry *lib.Entry) []string {
	domains, suffixes, keywords, regexes := entry.GetDomainRulesByType()
	var lines []string

	switch t.Format {
	case "v2fly":
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainSuffix] {
			lines = append(lines, suffixes...)
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomain] {
			for _, d := range domains {
				lines = append(lines, "full:"+d)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainKeyword] {
			for _, k := range keywords {
				lines = append(lines, "keyword:"+k)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainRegex] {
			for _, r := range regexes {
				lines = append(lines, "regexp:"+r)
			}
		}
		slices.Sort(lines)

	case "tld":
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainSuffix] {
			for _, d := range suffixes {
				if !lib.IsValidMultiLabelDomain(d) {
					lines = append(lines, d)
				}
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomain] {
			for _, d := range domains {
				line := "full:" + d
				if !lib.IsValidMultiLabelDomain(line) {
					lines = append(lines, line)
				}
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainKeyword] {
			for _, k := range keywords {
				lines = append(lines, "keyword:"+k)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainRegex] {
			for _, r := range regexes {
				lines = append(lines, "regexp:"+r)
			}
		}
		slices.Sort(lines)

	default:
		if !t.ExcludeRuleTypes[lib.RuleTypeDomain] {
			for _, d := range domains {
				lines = append(lines, "full:"+d)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainSuffix] {
			for _, d := range suffixes {
				lines = append(lines, "domain:"+d)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainKeyword] {
			for _, k := range keywords {
				lines = append(lines, "keyword:"+k)
			}
		}
		if !t.ExcludeRuleTypes[lib.RuleTypeDomainRegex] {
			for _, r := range regexes {
				lines = append(lines, "regexp:"+r)
			}
		}
	}

	return lines
}

type textIPOut struct {
	Type            string
	Action          lib.Action
	Description     string
	OutputDir       string
	OutputExt       string
	Want            []string
	Exclude         []string
	OnlyIPType      lib.IPType
	AddPrefixInLine string
	AddSuffixInLine string
}

func NewTextIPOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir       string     `json:"outputDir"`
		OutputExt       string     `json:"outputExtension"`
		Want            []string   `json:"wantedList"`
		Exclude         []string   `json:"excludedList"`
		OnlyIPType      lib.IPType `json:"onlyIPType"`
		AddPrefixInLine string     `json:"addPrefixInLine"`
		AddSuffixInLine string     `json:"addSuffixInLine"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeTextIPOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultTextIPOutputDir
	}
	outputExt := strings.TrimSpace(tmp.OutputExt)
	if outputExt == "" {
		outputExt = ".txt"
	}

	return &textIPOut{
		Type:            TypeTextIPOut,
		Action:          action,
		Description:     DescTextIPOut,
		OutputDir:       outputDir,
		OutputExt:       outputExt,
		Want:            tmp.Want,
		Exclude:         tmp.Exclude,
		OnlyIPType:      tmp.OnlyIPType,
		AddPrefixInLine: tmp.AddPrefixInLine,
		AddSuffixInLine: tmp.AddSuffixInLine,
	}, nil
}

func (t *textIPOut) GetType() string {
	return t.Type
}

func (t *textIPOut) GetAction() lib.Action {
	return t.Action
}

func (t *textIPOut) GetDescription() string {
	return t.Description
}

func (t *textIPOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, t.Want, t.Exclude)
	if err := os.MkdirAll(t.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasIPRules() {
			continue
		}
		cidrs, err := entry.MarshalIPText(lib.GetIgnoreIPType(t.OnlyIPType))
		if err != nil {
			return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
		if len(cidrs) == 0 {
			continue
		}

		var buf bytes.Buffer
		for _, cidr := range cidrs {
			if t.AddPrefixInLine != "" {
				buf.WriteString(t.AddPrefixInLine)
			}
			buf.WriteString(cidr)
			if t.AddSuffixInLine != "" {
				buf.WriteString(t.AddSuffixInLine)
			}
			buf.WriteByte('\n')
		}

		filename := entry.GetLowerName() + t.OutputExt
		if err := os.WriteFile(filepath.Join(t.OutputDir, filename), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
		log.Printf("[%s] %s --> %s", t.Type, filename, t.OutputDir)
	}

	return nil
}

type textAdGuardOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	OutputName  string
	OutputExt   string
	Want        []string
	Exclude     []string
}

func NewTextAdGuardOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string   `json:"outputDir"`
		OutputName string   `json:"outputName"`
		OutputExt  string   `json:"outputExtension"`
		Want       []string `json:"wantedList"`
		Exclude    []string `json:"excludedList"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeTextAdGuardOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultTextAdGuardOutputDir
	}
	outputExt := strings.TrimSpace(tmp.OutputExt)
	if outputExt == "" {
		outputExt = ".txt"
	}

	return &textAdGuardOut{
		Type:        TypeTextAdGuardOut,
		Action:      action,
		Description: DescTextAdGuardOut,
		OutputDir:   outputDir,
		OutputName:  strings.TrimSpace(tmp.OutputName),
		OutputExt:   outputExt,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
	}, nil
}

func (t *textAdGuardOut) GetType() string {
	return t.Type
}

func (t *textAdGuardOut) GetAction() lib.Action {
	return t.Action
}

func (t *textAdGuardOut) GetDescription() string {
	return t.Description
}

func (t *textAdGuardOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, t.Want, t.Exclude)
	if err := os.MkdirAll(t.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasAdGuardRules() {
			continue
		}
		rules := entry.GetAdGuardRules()
		if len(rules) == 0 {
			continue
		}

		var buf bytes.Buffer
		for _, r := range rules {
			buf.WriteString(r)
			buf.WriteByte('\n')
		}

		filename := entry.GetLowerName() + t.OutputExt
		if t.OutputName != "" && len(names) == 1 {
			filename = t.OutputName
		}

		if err := os.WriteFile(filepath.Join(t.OutputDir, filename), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
		log.Printf("[%s] %s --> %s", t.Type, filename, t.OutputDir)
	}

	return nil
}
