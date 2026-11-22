package singbox

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	TypeSingboxIPOut = "singboxIP"
	DescSingboxIPOut = "Convert IP/CIDR rules to sing-box rule-set (.srs and .json)"
)

var (
	defaultIPOutputDir = filepath.Join("./", "rule_set", "rule_set_ip")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeSingboxIPOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewIPOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeSingboxIPOut, &ipOut{
		Description: DescSingboxIPOut,
	})
}

type ipOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	Want        []string
	Exclude     []string
	OnlyIPType  lib.IPType
	Version     uint8
	WriteSRS    bool
	WriteJSON   bool
}

func NewIPOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string     `json:"outputDir"`
		Want       []string   `json:"wantedList"`
		Exclude    []string   `json:"excludedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
		Version    uint8      `json:"version"`
		WriteSRS   *bool      `json:"writeSRS"`
		WriteJSON  *bool      `json:"writeJSON"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSingboxIPOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultIPOutputDir
	}
	version := tmp.Version
	if version == 0 {
		version = constant.RuleSetVersion4
	}
	if version > constant.RuleSetVersionCurrent {
		return nil, fmt.Errorf("[type %s | action %s] unsupported rule-set version %d", TypeSingboxIPOut, action, version)
	}

	writeSRS := true
	if tmp.WriteSRS != nil {
		writeSRS = *tmp.WriteSRS
	}
	writeJSON := true
	if tmp.WriteJSON != nil {
		writeJSON = *tmp.WriteJSON
	}

	return &ipOut{
		Type:        TypeSingboxIPOut,
		Action:      action,
		Description: DescSingboxIPOut,
		OutputDir:   outputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,
		Version:     version,
		WriteSRS:    writeSRS,
		WriteJSON:   writeJSON,
	}, nil
}

func (s *ipOut) GetType() string {
	return s.Type
}

func (s *ipOut) GetAction() lib.Action {
	return s.Action
}

func (s *ipOut) GetDescription() string {
	return s.Description
}

func (s *ipOut) Output(container lib.Container) error {
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

		plainRuleSet := option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type: constant.RuleTypeDefault,
					DefaultOptions: option.DefaultHeadlessRule{
						IPCIDR: cidrs,
					},
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
