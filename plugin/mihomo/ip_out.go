package mihomo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	P "github.com/metacubex/mihomo/constant/provider"
)

const (
	TypeMihomoIPOut = "mihomoIP"
	DescMihomoIPOut = "Convert IP/CIDR rules to mihomo rule-set (.mrs and .yaml)"
)

var (
	defaultIPOutputDir = filepath.Join("./", "rule-set", "mihomo", "geoip")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeMihomoIPOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewIPOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeMihomoIPOut, &ipOut{
		Description: DescMihomoIPOut,
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
	WriteMRS    bool
	WriteYAML   bool
}

func NewIPOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string     `json:"outputDir"`
		Want       []string   `json:"wantedList"`
		Exclude    []string   `json:"excludedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
		WriteMRS   *bool      `json:"writeMRS"`
		WriteYAML  *bool      `json:"writeYAML"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeMihomoIPOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultIPOutputDir
	}

	writeMRS := true
	if tmp.WriteMRS != nil {
		writeMRS = *tmp.WriteMRS
	}
	writeYAML := true
	if tmp.WriteYAML != nil {
		writeYAML = *tmp.WriteYAML
	}

	return &ipOut{
		Type:        TypeMihomoIPOut,
		Action:      action,
		Description: DescMihomoIPOut,
		OutputDir:   outputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,
		WriteMRS:    writeMRS,
		WriteYAML:   writeYAML,
	}, nil
}

func (m *ipOut) GetType() string {
	return m.Type
}

func (m *ipOut) GetAction() lib.Action {
	return m.Action
}

func (m *ipOut) GetDescription() string {
	return m.Description
}

func (m *ipOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, m.Want, m.Exclude)
	if err := os.MkdirAll(m.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasIPRules() {
			continue
		}

		cidrs, err := entry.MarshalIPText(lib.GetIgnoreIPType(m.OnlyIPType))
		if err != nil {
			return fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
		}
		if len(cidrs) == 0 {
			continue
		}

		baseName := entry.GetLowerName()
		if m.WriteYAML {
			var yamlBuf bytes.Buffer
			yamlBuf.WriteString("payload:\n")
			for _, cidr := range cidrs {
				yamlBuf.WriteString("  - '")
				yamlBuf.WriteString(cidr)
				yamlBuf.WriteString("'\n")
			}
			if err := os.WriteFile(filepath.Join(m.OutputDir, baseName+".yaml"), yamlBuf.Bytes(), 0644); err != nil {
				return fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
			}
			log.Printf("[%s] %s.yaml --> %s", m.Type, baseName, m.OutputDir)
		}

		if m.WriteMRS {
			var textBuf bytes.Buffer
			for _, cidr := range cidrs {
				textBuf.WriteString(cidr)
				textBuf.WriteByte('\n')
			}
			if err := writeMRS(m.OutputDir, baseName+".mrs", textBuf.Bytes(), P.IPCIDR); err != nil {
				return fmt.Errorf("[type %s | action %s] entry %s: %w", m.Type, m.Action, name, err)
			}
			log.Printf("[%s] %s.mrs --> %s", m.Type, baseName, m.OutputDir)
		}
	}

	return nil
}
