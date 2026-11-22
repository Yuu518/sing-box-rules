package plaintext

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeGFWListDomainIn = "gfwlistDomain"
	DescGFWListDomainIn = "Fetch and decode GFWList (Base64 AutoProxy format) into domain suffix rules"
	defaultGFWListURI   = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
)

func init() {
	lib.RegisterInputConfigCreator(TypeGFWListDomainIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewGFWListInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeGFWListDomainIn, &gfwlistIn{
		Description: DescGFWListDomainIn,
	})
}

type gfwlistIn struct {
	Type        string
	Action      lib.Action
	Description string
	Names       []string
	URI         string
}

func NewGFWListInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name  string   `json:"name"`
		Names []string `json:"names"`
		URI   string   `json:"uri"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeGFWListDomainIn, action, err)
		}
	}

	names := make([]string, 0, len(tmp.Names)+1)
	if n := strings.TrimSpace(tmp.Name); n != "" {
		names = append(names, n)
	}
	for _, n := range tmp.Names {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}

	uri := strings.TrimSpace(tmp.URI)
	if uri == "" {
		uri = defaultGFWListURI
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("[type %s | action %s] missing name or names", TypeGFWListDomainIn, action)
	}

	return &gfwlistIn{
		Type:        TypeGFWListDomainIn,
		Action:      action,
		Description: DescGFWListDomainIn,
		Names:       names,
		URI:         uri,
	}, nil
}

func (g *gfwlistIn) GetType() string {
	return g.Type
}

func (g *gfwlistIn) GetAction() lib.Action {
	return g.Action
}

func (g *gfwlistIn) GetDescription() string {
	return g.Description
}

func (g *gfwlistIn) Input(container lib.Container) (lib.Container, error) {
	raw, err := lib.ReadURIContent(g.URI)
	if err != nil {
		return nil, fmt.Errorf("[type %s | action %s] %w", g.Type, g.Action, err)
	}

	decoded := decodeGFWList(raw)
	domains := extractGFWListDomains(decoded)

	for _, name := range g.Names {
		entry := lib.NewEntry(name)
		for _, domain := range domains {
			entry.AddDomainRule(lib.DomainRule{
				Type:  lib.RuleTypeDomainSuffix,
				Value: domain,
			})
		}

		switch g.Action {
		case lib.ActionAdd:
			if err := container.Add(entry); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", g.Type, g.Action, err)
			}
		case lib.ActionReplace:
			if err := container.Replace(entry, lib.EntryKindDomain); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", g.Type, g.Action, err)
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindDomain); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", g.Type, g.Action, err)
			}
		default:
			return nil, fmt.Errorf("[type %s | action %s] unsupported action", g.Type, g.Action)
		}
	}

	return container, nil
}

func decodeGFWList(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("[AutoProxy")) {
		return trimmed
	}
	cleaned := bytes.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, trimmed)
	decoded, err := base64.StdEncoding.DecodeString(string(cleaned))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(string(cleaned))
		if err != nil {
			return raw
		}
	}
	return decoded
}

func extractGFWListDomains(data []byte) []string {
	seen := make(map[string]struct{})
	var domains []string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "@@") {
			continue
		}
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
			continue
		}

		domain := extractDomainFromGFWLine(line)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; !ok {
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains
}

func extractDomainFromGFWLine(line string) string {
	s := line
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimPrefix(s, "|")
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	s = strings.TrimLeft(s, ".")
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.LastIndex(s, "@"); idx >= 0 {
		s = s[idx+1:]
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	if strings.Contains(s, "*") {
		parts := strings.Split(s, "*")
		s = parts[len(parts)-1]
	}
	s = strings.Trim(s, ". ")
	s = strings.ToLower(s)
	if s == "" || !strings.Contains(s, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	if !lib.IsValidMultiLabelDomain(s) {
		return ""
	}
	return s
}
