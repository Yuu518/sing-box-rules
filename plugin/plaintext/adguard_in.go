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
	TypeAdGuardIn = "adguard"
	DescAdGuardIn = "Load AdGuard DNS filter rules from file, URL, S3/R2, or inline list"
)

func init() {
	lib.RegisterInputConfigCreator(TypeAdGuardIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewAdGuardInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeAdGuardIn, &adguardIn{
		Description: DescAdGuardIn,
	})
}

type adguardIn struct {
	Type        string
	Action      lib.Action
	Description string
	Names       []string
	URI         string
	Rules       []string
	SkipLines   int
	KeepRaw     bool
}

func NewAdGuardInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name      string   `json:"name"`
		Names     []string `json:"names"`
		URI       string   `json:"uri"`
		Rules     []string `json:"rules"`
		SkipLines int      `json:"skipLines"`
		KeepRaw   bool     `json:"keepRaw"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeAdGuardIn, action, err)
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

	a := &adguardIn{
		Type:        TypeAdGuardIn,
		Action:      action,
		Description: DescAdGuardIn,
		Names:       names,
		URI:         strings.TrimSpace(tmp.URI),
		Rules:       tmp.Rules,
		SkipLines:   tmp.SkipLines,
		KeepRaw:     tmp.KeepRaw,
	}

	if len(a.Names) == 0 {
		return nil, fmt.Errorf("[type %s | action %s] missing name or names", a.Type, a.Action)
	}
	if a.URI == "" && len(a.Rules) == 0 {
		return nil, fmt.Errorf("[type %s | action %s] missing uri or rules", a.Type, a.Action)
	}

	return a, nil
}

func (a *adguardIn) GetType() string {
	return a.Type
}

func (a *adguardIn) GetAction() lib.Action {
	return a.Action
}

func (a *adguardIn) GetDescription() string {
	return a.Description
}

func isAdGuardNonRule(line string) bool {
	if line == "" {
		return true
	}
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return true
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return true
	}
	for _, marker := range []string{"##", "#@#", "#?#", "#$#", "#%#"} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func (a *adguardIn) Input(container lib.Container) (lib.Container, error) {
	var lines []string

	if a.URI != "" {
		content, err := lib.ReadURIContent(a.URI)
		if err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			if lineNo <= a.SkipLines {
				continue
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if !a.KeepRaw && isAdGuardNonRule(line) {
				continue
			}
			lines = append(lines, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
		}
	}

	for _, r := range a.Rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !a.KeepRaw && isAdGuardNonRule(r) {
			continue
		}
		lines = append(lines, r)
	}

	for _, name := range a.Names {
		entry := lib.NewEntry(name)
		for _, line := range lines {
			entry.AddAdGuardRule(line)
		}

		switch a.Action {
		case lib.ActionAdd:
			if err := container.Add(entry); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
			}
		case lib.ActionReplace:
			if err := container.Replace(entry, lib.EntryKindAdGuard); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindAdGuard); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", a.Type, a.Action, err)
			}
		default:
			return nil, fmt.Errorf("[type %s | action %s] unsupported action", a.Type, a.Action)
		}
	}

	return container, nil
}
