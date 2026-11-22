package special

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
)

const (
	TypeCutter = "cutter"
	DescCutter = "Remove entries or specific rule kinds from previous steps"
)

func init() {
	lib.RegisterInputConfigCreator(TypeCutter, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewCutterFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeCutter, &cutter{
		Description: DescCutter,
	})
}

type cutter struct {
	Type        string
	Action      lib.Action
	Description string
	Want        map[string]bool
	Kind        lib.EntryKind
	OnlyIPType  lib.IPType
}

func NewCutterFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Want       []string      `json:"wantedList"`
		Kind       lib.EntryKind `json:"kind"`
		OnlyIPType lib.IPType    `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeCutter, action, err)
		}
	}

	if action != lib.ActionRemove {
		return nil, fmt.Errorf("[type %s | action %s] only supports remove action", TypeCutter, action)
	}

	wantMap := make(map[string]bool)
	for _, w := range tmp.Want {
		if w = strings.ToUpper(strings.TrimSpace(w)); w != "" {
			wantMap[w] = true
		}
	}
	if len(wantMap) == 0 {
		return nil, fmt.Errorf("[type %s | action %s] wantedList must be specified", TypeCutter, action)
	}

	return &cutter{
		Type:        TypeCutter,
		Action:      action,
		Description: DescCutter,
		Want:        wantMap,
		Kind:        lib.EntryKind(strings.ToLower(strings.TrimSpace(string(tmp.Kind)))),
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

func (c *cutter) GetType() string {
	return c.Type
}

func (c *cutter) GetAction() lib.Action {
	return c.Action
}

func (c *cutter) GetDescription() string {
	return c.Description
}

func (c *cutter) Input(container lib.Container) (lib.Container, error) {
	ignoreIPType := lib.GetIgnoreIPType(c.OnlyIPType)
	for entry := range container.Loop() {
		if !c.Want[entry.GetName()] {
			continue
		}
		if err := container.Remove(entry, lib.CaseRemoveEntry, c.Kind, ignoreIPType); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", c.Type, c.Action, err)
		}
	}
	return container, nil
}
