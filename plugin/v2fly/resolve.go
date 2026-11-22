package v2fly

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeV2FlyResolve = "v2flyResolve"
	DescV2FlyResolve = "Resolve v2fly include directives and materialize @attr sub-entries"
)

func init() {
	lib.RegisterInputConfigCreator(TypeV2FlyResolve, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewResolveFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeV2FlyResolve, &resolver{
		Description: DescV2FlyResolve,
	})
}

type resolver struct {
	Type                string
	Action              lib.Action
	Description         string
	GenerateAttrEntries bool
}

func NewResolveFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	tmp := struct {
		GenerateAttrEntries *bool `json:"generateAttrEntries"`
	}{}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeV2FlyResolve, action, err)
		}
	}

	genAttr := true
	if tmp.GenerateAttrEntries != nil {
		genAttr = *tmp.GenerateAttrEntries
	}

	return &resolver{
		Type:                TypeV2FlyResolve,
		Action:              action,
		Description:         DescV2FlyResolve,
		GenerateAttrEntries: genAttr,
	}, nil
}

func (r *resolver) GetType() string {
	return r.Type
}

func (r *resolver) GetAction() lib.Action {
	return r.Action
}

func (r *resolver) GetDescription() string {
	return r.Description
}

func (r *resolver) Input(container lib.Container) (lib.Container, error) {
	resolvedCache := make(map[string][]lib.DomainRule)
	visiting := make(map[string]bool)

	var resolveEntry func(name string) []lib.DomainRule
	resolveEntry = func(name string) []lib.DomainRule {
		if cached, ok := resolvedCache[name]; ok {
			return cached
		}
		entry, found := container.GetEntry(name)
		if !found {
			return nil
		}
		if visiting[name] {
			return entry.GetDomainRules()
		}
		visiting[name] = true

		temp := lib.NewEntry(name)
		for _, rule := range entry.GetDomainRules() {
			temp.AddDomainRule(rule)
		}
		for _, inc := range entry.GetIncludes() {
			childRules := resolveEntry(inc.Target)
			for _, cr := range childRules {
				if inc.Attr != "" {
					has := cr.HasAttr(inc.Attr)
					if inc.Negate && has {
						continue
					}
					if !inc.Negate && !has {
						continue
					}
				}
				temp.AddDomainRule(cr)
			}
		}

		visiting[name] = false
		rules := temp.GetDomainRules()
		resolvedCache[name] = rules
		return rules
	}

	names := container.SortedNames()
	for _, name := range names {
		entry, ok := container.GetEntry(name)
		if !ok {
			continue
		}
		if !entry.HasDomainRules() && !entry.HasIncludes() {
			continue
		}
		rules := resolveEntry(name)
		entry.ClearIncludes()
		for _, rule := range rules {
			entry.AddDomainRule(rule)
		}
	}

	if r.GenerateAttrEntries {
		for _, name := range names {
			if strings.Contains(name, "@") {
				continue
			}
			entry, ok := container.GetEntry(name)
			if !ok || !entry.HasDomainRules() {
				continue
			}
			attrMap := make(map[string][]lib.DomainRule)
			for _, rule := range entry.GetDomainRules() {
				for _, attr := range rule.Attrs {
					attrMap[attr] = append(attrMap[attr], rule)
				}
			}
			for attr, rules := range attrMap {
				subName := fmt.Sprintf("%s@%s", name, strings.ToUpper(attr))
				subEntry := lib.NewEntry(subName)
				for _, rule := range rules {
					subEntry.AddDomainRule(rule)
				}
				if err := container.Add(subEntry); err != nil {
					return nil, fmt.Errorf("[type %s | action %s] %w", r.Type, r.Action, err)
				}
			}
		}
	}

	return container, nil
}
