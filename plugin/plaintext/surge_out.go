package plaintext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeSurgeDomainOut = "surgeDomain"
	DescSurgeDomainOut = "Convert domain rules to Surge ruleset (.list)"
	TypeSurgeIPOut     = "surgeIP"
	DescSurgeIPOut     = "Convert IP/CIDR rules to Surge ruleset (.list)"
)

var (
	defaultSurgeSiteOutputDir = filepath.Join("./", "rule-set", "surge", "geosite")
	defaultSurgeIPOutputDir   = filepath.Join("./", "rule-set", "surge", "geoip")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeSurgeDomainOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewSurgeSiteOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeSurgeDomainOut, &surgeSiteOut{
		Description: DescSurgeDomainOut,
	})

	lib.RegisterOutputConfigCreator(TypeSurgeIPOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewSurgeIPOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeSurgeIPOut, &surgeIPOut{
		Description: DescSurgeIPOut,
	})
}

type surgeSiteOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	OutputExt   string
	Want        []string
	Exclude     []string
}

func NewSurgeSiteOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir string   `json:"outputDir"`
		OutputExt string   `json:"outputExtension"`
		Want      []string `json:"wantedList"`
		Exclude   []string `json:"excludedList"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSurgeDomainOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultSurgeSiteOutputDir
	}
	outputExt := strings.TrimSpace(tmp.OutputExt)
	if outputExt == "" {
		outputExt = ".list"
	}

	return &surgeSiteOut{
		Type:        TypeSurgeDomainOut,
		Action:      action,
		Description: DescSurgeDomainOut,
		OutputDir:   outputDir,
		OutputExt:   outputExt,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
	}, nil
}

func (s *surgeSiteOut) GetType() string {
	return s.Type
}

func (s *surgeSiteOut) GetAction() lib.Action {
	return s.Action
}

func (s *surgeSiteOut) GetDescription() string {
	return s.Description
}

func (s *surgeSiteOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, s.Want, s.Exclude)
	if err := os.MkdirAll(s.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasDomainRules() {
			continue
		}

		domains, suffixes, keywords, regexes := entry.GetDomainRulesByType()
		var buf bytes.Buffer
		for _, d := range domains {
			buf.WriteString("DOMAIN,")
			buf.WriteString(d)
			buf.WriteByte('\n')
		}
		for _, d := range suffixes {
			buf.WriteString("DOMAIN-SUFFIX,")
			buf.WriteString(d)
			buf.WriteByte('\n')
		}
		for _, k := range keywords {
			buf.WriteString("DOMAIN-KEYWORD,")
			buf.WriteString(k)
			buf.WriteByte('\n')
		}
		for _, r := range regexes {
			buf.WriteString("DOMAIN-REGEX,")
			buf.WriteString(r)
			buf.WriteByte('\n')
		}

		if buf.Len() == 0 {
			continue
		}

		filename := entry.GetLowerName() + s.OutputExt
		if err := os.WriteFile(filepath.Join(s.OutputDir, filename), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
		}
		log.Printf("[%s] %s --> %s", s.Type, filename, s.OutputDir)
	}

	return nil
}

type surgeIPOut struct {
	Type            string
	Action          lib.Action
	Description     string
	OutputDir       string
	OutputExt       string
	Want            []string
	Exclude         []string
	OnlyIPType      lib.IPType
	AddSuffixInLine string
}

func NewSurgeIPOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir       string     `json:"outputDir"`
		OutputExt       string     `json:"outputExtension"`
		Want            []string   `json:"wantedList"`
		Exclude         []string   `json:"excludedList"`
		OnlyIPType      lib.IPType `json:"onlyIPType"`
		AddSuffixInLine string     `json:"addSuffixInLine"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSurgeIPOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultSurgeIPOutputDir
	}
	outputExt := strings.TrimSpace(tmp.OutputExt)
	if outputExt == "" {
		outputExt = ".list"
	}

	return &surgeIPOut{
		Type:            TypeSurgeIPOut,
		Action:          action,
		Description:     DescSurgeIPOut,
		OutputDir:       outputDir,
		OutputExt:       outputExt,
		Want:            tmp.Want,
		Exclude:         tmp.Exclude,
		OnlyIPType:      tmp.OnlyIPType,
		AddSuffixInLine: tmp.AddSuffixInLine,
	}, nil
}

func (s *surgeIPOut) GetType() string {
	return s.Type
}

func (s *surgeIPOut) GetAction() lib.Action {
	return s.Action
}

func (s *surgeIPOut) GetDescription() string {
	return s.Description
}

func (s *surgeIPOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, s.Want, s.Exclude)
	if err := os.MkdirAll(s.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasIPRules() {
			continue
		}

		cidrs, err := entry.MarshalIPText(lib.GetIgnoreIPType(s.OnlyIPType))
		if err != nil {
			return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
		}
		if len(cidrs) == 0 {
			continue
		}

		var buf bytes.Buffer
		for _, cidr := range cidrs {
			if strings.Contains(cidr, ":") {
				buf.WriteString("IP-CIDR6,")
			} else {
				buf.WriteString("IP-CIDR,")
			}
			buf.WriteString(cidr)
			if s.AddSuffixInLine != "" {
				buf.WriteString(s.AddSuffixInLine)
			}
			buf.WriteByte('\n')
		}

		filename := entry.GetLowerName() + s.OutputExt
		if err := os.WriteFile(filepath.Join(s.OutputDir, filename), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
		}
		log.Printf("[%s] %s --> %s", s.Type, filename, s.OutputDir)
	}

	return nil
}
