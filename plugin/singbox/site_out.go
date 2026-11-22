package singbox

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	TypeSingboxDomainOut = "singboxDomain"
	DescSingboxDomainOut = "Convert domain rules to sing-box rule-set (.srs and .json)"
)

var (
	defaultSiteOutputDir = filepath.Join("./", "rule_set", "rule_set_site")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeSingboxDomainOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewSiteOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeSingboxDomainOut, &siteOut{
		Description: DescSingboxDomainOut,
	})
}

type siteOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	Want        []string
	Exclude     []string
	Version     uint8
	WriteSRS    bool
	WriteJSON   bool
}

func NewSiteOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir string   `json:"outputDir"`
		Want      []string `json:"wantedList"`
		Exclude   []string `json:"excludedList"`
		Version   uint8    `json:"version"`
		WriteSRS  *bool    `json:"writeSRS"`
		WriteJSON *bool    `json:"writeJSON"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSingboxDomainOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultSiteOutputDir
	}
	version := tmp.Version
	if version == 0 {
		version = constant.RuleSetVersion4
	}
	if version > constant.RuleSetVersionCurrent {
		return nil, fmt.Errorf("[type %s | action %s] unsupported rule-set version %d", TypeSingboxDomainOut, action, version)
	}

	writeSRS := true
	if tmp.WriteSRS != nil {
		writeSRS = *tmp.WriteSRS
	}
	writeJSON := true
	if tmp.WriteJSON != nil {
		writeJSON = *tmp.WriteJSON
	}

	return &siteOut{
		Type:        TypeSingboxDomainOut,
		Action:      action,
		Description: DescSingboxDomainOut,
		OutputDir:   outputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		Version:     version,
		WriteSRS:    writeSRS,
		WriteJSON:   writeJSON,
	}, nil
}

func (s *siteOut) GetType() string {
	return s.Type
}

func (s *siteOut) GetAction() lib.Action {
	return s.Action
}

func (s *siteOut) GetDescription() string {
	return s.Description
}

func (s *siteOut) Output(container lib.Container) error {
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
		if len(domains) == 0 && len(suffixes) == 0 && len(keywords) == 0 && len(regexes) == 0 {
			continue
		}

		var headless option.DefaultHeadlessRule
		if len(domains) > 0 {
			headless.Domain = domains
		}
		if len(suffixes) > 0 {
			headless.DomainSuffix = suffixes
		}
		if len(keywords) > 0 {
			headless.DomainKeyword = keywords
		}
		if len(regexes) > 0 {
			headless.DomainRegex = regexes
		}

		plainRuleSet := option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type:           constant.RuleTypeDefault,
					DefaultOptions: headless,
				},
			},
		}

		baseName := entry.GetLowerName()
		if s.WriteJSON {
			if err := writeRuleSetJSON(s.OutputDir, baseName+".json", plainRuleSet, s.Version); err != nil {
				return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
			}
			log.Printf("[%s] %s.json --> %s", s.Type, baseName, s.OutputDir)
		}
		if s.WriteSRS {
			if err := writeRuleSetSRS(s.OutputDir, baseName+".srs", plainRuleSet, s.Version); err != nil {
				return fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
			}
			log.Printf("[%s] %s.srs --> %s", s.Type, baseName, s.OutputDir)
		}
	}

	return nil
}

func writeRuleSetJSON(outputDir, filename string, plain option.PlainRuleSet, version uint8) error {
	compat := option.PlainRuleSetCompat{
		Version: version,
		Options: plain,
	}
	encoded, err := json.MarshalIndent(compat, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(filepath.Join(outputDir, filename), encoded, 0644)
}

func writeRuleSetSRS(outputDir, filename string, plain option.PlainRuleSet, version uint8) error {
	fullPath := filepath.Join(outputDir, filename)
	f, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	if err := srs.Write(f, plain, version); err != nil {
		f.Close()
		os.Remove(fullPath)
		return err
	}
	return f.Close()
}
