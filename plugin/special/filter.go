package special

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeDomainFilter = "domainFilter"
	DescDomainFilter = "Filter domain rules in specified entries (valid domains, exclude suffixes, exclude types)"
)

func init() {
	lib.RegisterInputConfigCreator(TypeDomainFilter, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewDomainFilterFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeDomainFilter, &domainFilter{
		Description: DescDomainFilter,
	})
}

type domainFilter struct {
	Type             string
	Action           lib.Action
	Description      string
	Want             map[string]bool
	ValidDomainOnly  bool
	ExcludeSuffixes  []string
	ExcludeRuleTypes map[lib.RuleType]bool
}

func NewDomainFilterFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Want             []string `json:"wantedList"`
		ValidDomainOnly  bool     `json:"validDomainOnly"`
		ExcludeSuffixes  []string `json:"excludeSuffixes"`
		ExcludeRuleTypes []string `json:"excludeRuleTypes"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeDomainFilter, action, err)
		}
	}

	wantMap := make(map[string]bool)
	for _, w := range tmp.Want {
		if w = strings.ToUpper(strings.TrimSpace(w)); w != "" {
			wantMap[w] = true
		}
	}

	excludeSuffixes := make([]string, 0, len(tmp.ExcludeSuffixes))
	for _, s := range tmp.ExcludeSuffixes {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			excludeSuffixes = append(excludeSuffixes, s)
		}
	}

	excludeTypes := make(map[lib.RuleType]bool)
	for _, rt := range tmp.ExcludeRuleTypes {
		if rt = strings.ToLower(strings.TrimSpace(rt)); rt != "" {
			excludeTypes[lib.RuleType(rt)] = true
		}
	}

	return &domainFilter{
		Type:             TypeDomainFilter,
		Action:           action,
		Description:      DescDomainFilter,
		Want:             wantMap,
		ValidDomainOnly:  tmp.ValidDomainOnly,
		ExcludeSuffixes:  excludeSuffixes,
		ExcludeRuleTypes: excludeTypes,
	}, nil
}

func (f *domainFilter) GetType() string {
	return f.Type
}

func (f *domainFilter) GetAction() lib.Action {
	return f.Action
}

func (f *domainFilter) GetDescription() string {
	return f.Description
}

func (f *domainFilter) Input(container lib.Container) (lib.Container, error) {
	for _, name := range container.SortedNames() {
		if len(f.Want) > 0 && !f.Want[name] {
			continue
		}
		entry, ok := container.GetEntry(name)
		if !ok || !entry.HasDomainRules() {
			continue
		}

		for _, rule := range entry.GetDomainRules() {
			if f.shouldRemove(rule) {
				entry.RemoveDomainRule(rule.Type, rule.Value)
			}
		}
	}
	return container, nil
}

func (f *domainFilter) shouldRemove(rule lib.DomainRule) bool {
	if f.ExcludeRuleTypes[rule.Type] {
		return true
	}

	if rule.Type == lib.RuleTypeDomainSuffix {
		if f.ValidDomainOnly && !lib.IsValidDomainOrTLD(rule.Value) {
			return true
		}
		for _, suffix := range f.ExcludeSuffixes {
			if strings.HasSuffix(rule.Value, suffix) {
				return true
			}
		}
	}

	return false
}
