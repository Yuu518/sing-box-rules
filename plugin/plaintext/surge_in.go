package plaintext

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeSurgeDomainIn = "surgeDomain"
	DescSurgeDomainIn = "Load domain rules from Surge domainset or classical ruleset format"
)

func init() {
	lib.RegisterInputConfigCreator(TypeSurgeDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewSurgeDomainInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeSurgeDomainIn, &surgeDomainIn{
		Description: DescSurgeDomainIn,
	})
}

type surgeDomainIn struct {
	Type        string
	Action      lib.Action
	Description string
	Name        string
	URI         string
	SkipEntries int
	BareAsFull  bool
}

func NewSurgeDomainInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name        string `json:"name"`
		URI         string `json:"uri"`
		SkipEntries int    `json:"skipEntries"`
		BareAsFull  bool   `json:"bareAsFull"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeSurgeDomainIn, action, err)
		}
	}

	s := &surgeDomainIn{
		Type:        TypeSurgeDomainIn,
		Action:      action,
		Description: DescSurgeDomainIn,
		Name:        strings.TrimSpace(tmp.Name),
		URI:         strings.TrimSpace(tmp.URI),
		SkipEntries: tmp.SkipEntries,
		BareAsFull:  tmp.BareAsFull,
	}

	if s.Name == "" || s.URI == "" {
		return nil, fmt.Errorf("[type %s | action %s] name and uri are required", s.Type, s.Action)
	}

	return s, nil
}

func (s *surgeDomainIn) GetType() string {
	return s.Type
}

func (s *surgeDomainIn) GetAction() lib.Action {
	return s.Action
}

func (s *surgeDomainIn) GetDescription() string {
	return s.Description
}

func (s *surgeDomainIn) Input(container lib.Container) (lib.Container, error) {
	content, err := lib.ReadURIContent(s.URI)
	if err != nil {
		return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	entry := lib.NewEntry(s.Name)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	seenEntries := 0

	for scanner.Scan() {
		line := scanner.Text()
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, "//")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		seenEntries++
		if seenEntries <= s.SkipEntries {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		if rule, ok := parseSurgeDomainLine(line, s.BareAsFull); ok {
			entry.AddDomainRule(rule)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("[type %s | action %s] %w", s.Type, s.Action, err)
	}

	switch s.Action {
	case lib.ActionAdd:
		return container, container.Add(entry)
	case lib.ActionReplace:
		return container, container.Replace(entry, lib.EntryKindDomain)
	case lib.ActionRemove:
		return container, container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindDomain)
	default:
		return nil, fmt.Errorf("[type %s | action %s] unsupported action", s.Type, s.Action)
	}
}

func parseSurgeDomainLine(line string, bareAsFull bool) (lib.DomainRule, bool) {
	upper := strings.ToUpper(line)
	if strings.Contains(line, ",") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			return lib.DomainRule{}, false
		}
		kind := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			return lib.DomainRule{}, false
		}
		switch kind {
		case "DOMAIN":
			return lib.DomainRule{Type: lib.RuleTypeDomain, Value: strings.ToLower(val)}, true
		case "DOMAIN-SUFFIX":
			return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: strings.ToLower(strings.TrimPrefix(val, "."))}, true
		case "DOMAIN-KEYWORD":
			return lib.DomainRule{Type: lib.RuleTypeDomainKeyword, Value: strings.ToLower(val)}, true
		case "DOMAIN-REGEX":
			return lib.DomainRule{Type: lib.RuleTypeDomainRegex, Value: val}, true
		default:
			return lib.DomainRule{}, false
		}
	}

	if strings.HasPrefix(upper, "IP-CIDR") || strings.HasPrefix(upper, "USER-AGENT") || strings.HasPrefix(upper, "PROCESS-NAME") {
		return lib.DomainRule{}, false
	}

	if strings.HasPrefix(line, "+.") {
		val := strings.ToLower(strings.TrimPrefix(line, "+."))
		if val == "" {
			return lib.DomainRule{}, false
		}
		return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val}, true
	}

	if strings.HasPrefix(line, ".") {
		val := strings.ToLower(strings.TrimPrefix(line, "."))
		if val == "" {
			return lib.DomainRule{}, false
		}
		return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val}, true
	}

	val := strings.ToLower(line)
	if !lib.IsValidDomainOrTLD(val) {
		return lib.DomainRule{}, false
	}
	if bareAsFull {
		return lib.DomainRule{Type: lib.RuleTypeDomain, Value: val}, true
	}
	return lib.DomainRule{Type: lib.RuleTypeDomainSuffix, Value: val}, true
}
