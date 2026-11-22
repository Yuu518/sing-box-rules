package plaintext

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeDnsmasqDomainIn = "dnsmasqDomain"
	DescDnsmasqDomainIn = "Load domain rules from dnsmasq config format (server=/domain/...)"
)

var (
	dnsmasqServerRegex = regexp.MustCompile(`^(?:server|local)=/([^/]+)/`)
	dnsmasqAnyRegex    = regexp.MustCompile(`^(?:server|local|address|ipset|nftset)=/([^/]+)/`)
)

func init() {
	lib.RegisterInputConfigCreator(TypeDnsmasqDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewDnsmasqInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeDnsmasqDomainIn, &dnsmasqIn{
		Description: DescDnsmasqDomainIn,
	})
}

type dnsmasqIn struct {
	Type        string
	Action      lib.Action
	Description string
	Name        string
	URI         string
}

func NewDnsmasqInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeDnsmasqDomainIn, action, err)
		}
	}

	d := &dnsmasqIn{
		Type:        TypeDnsmasqDomainIn,
		Action:      action,
		Description: DescDnsmasqDomainIn,
		Name:        strings.TrimSpace(tmp.Name),
		URI:         strings.TrimSpace(tmp.URI),
	}

	if d.Name == "" || d.URI == "" {
		return nil, fmt.Errorf("[type %s | action %s] name and uri are required", d.Type, d.Action)
	}

	return d, nil
}

func (d *dnsmasqIn) GetType() string {
	return d.Type
}

func (d *dnsmasqIn) GetAction() lib.Action {
	return d.Action
}

func (d *dnsmasqIn) GetDescription() string {
	return d.Description
}

func (d *dnsmasqIn) Input(container lib.Container) (lib.Container, error) {
	content, err := lib.ReadURIContent(d.URI)
	if err != nil {
		return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
	}

	entry := lib.NewEntry(d.Name)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := dnsmasqServerRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(matches[1], ".")))
		if domain != "" {
			entry.AddDomainRule(lib.DomainRule{
				Type:  lib.RuleTypeDomainSuffix,
				Value: domain,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("[type %s | action %s] %w", d.Type, d.Action, err)
	}

	switch d.Action {
	case lib.ActionAdd:
		return container, container.Add(entry)
	case lib.ActionReplace:
		return container, container.Replace(entry, lib.EntryKindDomain)
	case lib.ActionRemove:
		return container, container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindDomain)
	default:
		return nil, fmt.Errorf("[type %s | action %s] unsupported action", d.Type, d.Action)
	}
}
