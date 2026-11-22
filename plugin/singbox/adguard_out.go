package singbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/sagernet/sing-box/common/convertor/adguard"
	"github.com/sagernet/sing-box/constant"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

const (
	TypeSingboxAdGuardOut = "singboxAdGuard"
	DescSingboxAdGuardOut = "Convert AdGuard DNS filter rules to sing-box rule-set (.srs)"
)

func init() {
	lib.RegisterOutputConfigCreator(TypeSingboxAdGuardOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewAdGuardOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeSingboxAdGuardOut, &adguardOut{
		Description: DescSingboxAdGuardOut,
	})
}

type adguardOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	OutputName  string
	Want        []string
	Exclude     []string
	Version     uint8
}

func NewAdGuardOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string   `json:"outputDir"`
		OutputName string   `json:"outputName"`
		Want       []string `json:"wantedList"`
		Exclude    []string `json:"excludedList"`
		Version    uint8    `json:"version"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSingboxAdGuardOut, action, err)
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
	if version < constant.RuleSetVersion2 || version > constant.RuleSetVersionCurrent {
		return nil, fmt.Errorf("[type %s | action %s] unsupported AdGuard rule-set version %d", TypeSingboxAdGuardOut, action, version)
	}

	return &adguardOut{
		Type:        TypeSingboxAdGuardOut,
		Action:      action,
		Description: DescSingboxAdGuardOut,
		OutputDir:   outputDir,
		OutputName:  strings.TrimSpace(tmp.OutputName),
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		Version:     version,
	}, nil
}

func (a *adguardOut) GetType() string {
	return a.Type
}

func (a *adguardOut) GetAction() lib.Action {
	return a.Action
}

func (a *adguardOut) GetDescription() string {
	return a.Description
}

func (a *adguardOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, a.Want, a.Exclude)
	if err := os.MkdirAll(a.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
	}

	logger := sblog.NewNOPFactory().Logger()
	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasAdGuardRules() {
			continue
		}

		rawRules := entry.GetAdGuardRules()
		if len(rawRules) == 0 {
			continue
		}

		var buf bytes.Buffer
		for _, r := range rawRules {
			buf.WriteString(r)
			buf.WriteByte('\n')
		}

		rules, err := adguard.ToOptions(&buf, logger)
		if err != nil {
			return fmt.Errorf("[type %s | action %s] entry %s: %w", a.Type, a.Action, name, err)
		}
		if len(rules) == 0 {
			continue
		}

		filename := entry.GetLowerName() + ".srs"
		if a.OutputName != "" && len(names) == 1 {
			filename = a.OutputName
		}

		if err := writeRuleSetSRS(a.OutputDir, filename, option.PlainRuleSet{Rules: rules}, a.Version); err != nil {
			return fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
		}
		log.Printf("[%s] %s --> %s", a.Type, filename, a.OutputDir)
	}

	return nil
}
