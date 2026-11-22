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
	"github.com/metacubex/mihomo/rules/provider"
)

const (
	TypeMihomoDomainOut = "mihomoDomain"
	DescMihomoDomainOut = "Convert domain rules to mihomo rule-set (.mrs and .yaml)"
)

var (
	defaultSiteOutputDir = filepath.Join("./", "rule-set", "mihomo", "geosite")
)

func init() {
	lib.RegisterOutputConfigCreator(TypeMihomoDomainOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return NewSiteOutFromBytes(action, data)
	})
	lib.RegisterOutputConverter(TypeMihomoDomainOut, &siteOut{
		Description: DescMihomoDomainOut,
	})
}

type siteOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	Want        []string
	Exclude     []string
	WriteMRS    bool
	WriteYAML   bool
}

func NewSiteOutFromBytes(action lib.Action, data []byte) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir string   `json:"outputDir"`
		Want      []string `json:"wantedList"`
		Exclude   []string `json:"excludedList"`
		WriteMRS  *bool    `json:"writeMRS"`
		WriteYAML *bool    `json:"writeYAML"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeMihomoDomainOut, action, err)
		}
	}

	outputDir := strings.TrimSpace(tmp.OutputDir)
	if outputDir == "" {
		outputDir = defaultSiteOutputDir
	}

	writeMRS := true
	if tmp.WriteMRS != nil {
		writeMRS = *tmp.WriteMRS
	}
	writeYAML := true
	if tmp.WriteYAML != nil {
		writeYAML = *tmp.WriteYAML
	}

	return &siteOut{
		Type:        TypeMihomoDomainOut,
		Action:      action,
		Description: DescMihomoDomainOut,
		OutputDir:   outputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		WriteMRS:    writeMRS,
		WriteYAML:   writeYAML,
	}, nil
}

func (m *siteOut) GetType() string {
	return m.Type
}

func (m *siteOut) GetAction() lib.Action {
	return m.Action
}

func (m *siteOut) GetDescription() string {
	return m.Description
}

func (m *siteOut) Output(container lib.Container) error {
	names := lib.FilterAndSortEntryNames(container, m.Want, m.Exclude)
	if err := os.MkdirAll(m.OutputDir, 0755); err != nil {
		return fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
	}

	for _, name := range names {
		entry, found := container.GetEntry(name)
		if !found || !entry.HasDomainRules() {
			continue
		}

		domains, suffixes, _, _ := entry.GetDomainRulesByType()
		lines := make([]string, 0, len(domains)+len(suffixes))
		for _, d := range domains {
			lines = append(lines, d)
		}
		for _, s := range suffixes {
			lines = append(lines, "+."+s)
		}
		if len(lines) == 0 {
			continue
		}

		baseName := entry.GetLowerName()
		if m.WriteYAML {
			var yamlBuf bytes.Buffer
			yamlBuf.WriteString("payload:\n")
			for _, line := range lines {
				yamlBuf.WriteString("  - '")
				yamlBuf.WriteString(line)
				yamlBuf.WriteString("'\n")
			}
			if err := os.WriteFile(filepath.Join(m.OutputDir, baseName+".yaml"), yamlBuf.Bytes(), 0644); err != nil {
				return fmt.Errorf("[type %s | action %s] %w", m.Type, m.Action, err)
			}
			log.Printf("[%s] %s.yaml --> %s", m.Type, baseName, m.OutputDir)
		}

		if m.WriteMRS {
			var textBuf bytes.Buffer
			for _, line := range lines {
				textBuf.WriteString(line)
				textBuf.WriteByte('\n')
			}
			if err := writeMRS(m.OutputDir, baseName+".mrs", textBuf.Bytes(), P.Domain); err != nil {
				log.Printf("[%s] skip %s.mrs: %v", m.Type, baseName, err)
				continue
			}
			log.Printf("[%s] %s.mrs --> %s", m.Type, baseName, m.OutputDir)
		}
	}

	return nil
}

func writeMRS(outputDir, filename string, textData []byte, behavior P.RuleBehavior) error {
	var mrsBuf bytes.Buffer
	if err := provider.ConvertToMrs(textData, behavior, P.TextRule, &mrsBuf); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, filename), mrsBuf.Bytes(), 0644)
}
