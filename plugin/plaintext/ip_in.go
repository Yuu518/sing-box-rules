package plaintext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/Yuu518/sing-box-rules/plugin/mihomo"
	"github.com/Yuu518/sing-box-rules/plugin/singbox"
	P "github.com/metacubex/mihomo/constant/provider"
)

const (
	TypeIPIn = "ip"
	DescIPIn = "Auto-detect and load IP/CIDR rules from plain text, sing-box SRS, or mihomo MRS via directory, file, URL, S3/R2, or inline list"
)

func init() {
	lib.RegisterInputConfigCreator(TypeIPIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewIPTextInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeIPIn, &ipTextIn{
		Description: DescIPIn,
	})
}

type ipTextIn struct {
	Type                 string
	Action               lib.Action
	Description          string
	Name                 string
	URI                  string
	IPOrCIDR             []string
	InputDir             string
	Want                 map[string]bool
	Exclude              map[string]bool
	OnlyIPType           lib.IPType
	RemovePrefixesInLine []string
	RemoveSuffixesInLine []string
	S3Endpoint           string
	S3Region             string
	S3Bucket             string
}

func NewIPTextInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	var tmp struct {
		Name                 string     `json:"name"`
		URI                  string     `json:"uri"`
		IPOrCIDR             []string   `json:"ipOrCIDR"`
		InputDir             string     `json:"inputDir"`
		Want                 []string   `json:"wantedList"`
		Exclude              []string   `json:"excludedList"`
		OnlyIPType           lib.IPType `json:"onlyIPType"`
		RemovePrefixesInLine []string   `json:"removePrefixesInLine"`
		RemoveSuffixesInLine []string   `json:"removeSuffixesInLine"`
		S3Endpoint           string     `json:"s3Endpoint"`
		S3Region             string     `json:"s3Region"`
		S3Bucket             string     `json:"s3Bucket"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", TypeIPIn, action, err)
		}
	}

	t := &ipTextIn{
		Type:                 TypeIPIn,
		Action:               action,
		Description:          DescIPIn,
		Name:                 strings.TrimSpace(tmp.Name),
		URI:                  strings.TrimSpace(tmp.URI),
		IPOrCIDR:             tmp.IPOrCIDR,
		InputDir:             strings.TrimSpace(tmp.InputDir),
		Want:                 toUpperMap(tmp.Want),
		Exclude:              toUpperMap(tmp.Exclude),
		OnlyIPType:           tmp.OnlyIPType,
		RemovePrefixesInLine: tmp.RemovePrefixesInLine,
		RemoveSuffixesInLine: tmp.RemoveSuffixesInLine,
		S3Endpoint:           strings.TrimSpace(tmp.S3Endpoint),
		S3Region:             strings.TrimSpace(tmp.S3Region),
		S3Bucket:             strings.TrimSpace(tmp.S3Bucket),
	}

	if t.InputDir == "" {
		if t.Name == "" {
			return nil, fmt.Errorf("[type %s | action %s] missing inputDir or name", t.Type, t.Action)
		}
		if t.URI == "" && len(t.IPOrCIDR) == 0 {
			return nil, fmt.Errorf("[type %s | action %s] missing uri or ipOrCIDR", t.Type, t.Action)
		}
	} else if t.Name != "" || t.URI != "" || len(t.IPOrCIDR) > 0 {
		return nil, fmt.Errorf("[type %s | action %s] inputDir cannot be used with name, uri, or ipOrCIDR", t.Type, t.Action)
	}

	return t, nil
}

func (t *ipTextIn) GetType() string {
	return t.Type
}

func (t *ipTextIn) GetAction() lib.Action {
	return t.Action
}

func (t *ipTextIn) GetDescription() string {
	return t.Description
}

func (t *ipTextIn) Input(container lib.Container) (lib.Container, error) {
	entries := make(map[string]*lib.Entry)

	switch {
	case t.InputDir != "" && lib.IsS3URI(t.InputDir):
		if err := t.readS3Dir(entries); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
	case t.InputDir != "":
		if err := t.readLocalDir(entries); err != nil {
			return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
		}
	default:
		entry := lib.NewEntry(t.Name)
		if t.URI != "" {
			var content []byte
			var err error
			if lib.IsS3URI(t.URI) {
				content, err = lib.ReadS3Object(t.URI, lib.S3Config{
					Endpoint: t.S3Endpoint,
					Region:   t.S3Region,
					Bucket:   t.S3Bucket,
				})
			} else {
				content, err = lib.ReadURIContent(t.URI)
			}
			if err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
			if err := t.scanBytes(content, entry); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
		}
		for _, cidr := range t.IPOrCIDR {
			if err := entry.AddPrefix(cidr); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
		}
		entries[entry.GetName()] = entry
	}

	ignoreIPType := lib.GetIgnoreIPType(t.OnlyIPType)
	for _, entry := range entries {
		switch t.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
		case lib.ActionReplace:
			if err := container.Replace(entry, lib.EntryKindIP, ignoreIPType); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemoveRule, lib.EntryKindIP, ignoreIPType); err != nil {
				return nil, fmt.Errorf("[type %s | action %s] %w", t.Type, t.Action, err)
			}
		default:
			return nil, fmt.Errorf("[type %s | action %s] unsupported action", t.Type, t.Action)
		}
	}

	return container, nil
}

func (t *ipTextIn) shouldLoad(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	if len(t.Want) > 0 && !t.Want[upper] {
		return false
	}
	if t.Exclude[upper] {
		return false
	}
	return true
}

func (t *ipTextIn) readLocalDir(entries map[string]*lib.Entry) error {
	dirEntries, err := os.ReadDir(t.InputDir)
	if err != nil {
		return err
	}
	for _, de := range dirEntries {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		name := strings.TrimSuffix(de.Name(), filepath.Ext(de.Name()))
		if !t.shouldLoad(name) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(t.InputDir, de.Name()))
		if err != nil {
			return err
		}
		entry := lib.NewEntry(name)
		if err := t.scanBytes(content, entry); err != nil {
			return fmt.Errorf("file %s: %w", de.Name(), err)
		}
		entries[entry.GetName()] = entry
	}
	return nil
}

func (t *ipTextIn) readS3Dir(entries map[string]*lib.Entry) error {
	bucket, prefix, err := lib.ParseS3URI(t.InputDir)
	if err != nil {
		return err
	}
	cfg := lib.S3Config{
		Endpoint: t.S3Endpoint,
		Region:   t.S3Region,
		Bucket:   t.S3Bucket,
	}
	if bucket != "" {
		cfg.Bucket = bucket
	}
	client, err := lib.NewS3Client(cfg)
	if err != nil {
		return err
	}
	ctx := context.Background()
	keys, err := client.ListObjects(ctx, cfg.Bucket, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		base := path.Base(key)
		if strings.HasPrefix(base, ".") {
			continue
		}
		name := strings.TrimSuffix(base, path.Ext(base))
		if !t.shouldLoad(name) {
			continue
		}
		content, err := client.GetObject(ctx, cfg.Bucket, key)
		if err != nil {
			return err
		}
		entry := lib.NewEntry(name)
		if err := t.scanBytes(content, entry); err != nil {
			return fmt.Errorf("file %s: %w", key, err)
		}
		entries[entry.GetName()] = entry
	}
	return nil
}

func (t *ipTextIn) scanBytes(raw []byte, entry *lib.Entry) error {
	if singbox.IsSRSBytes(raw) {
		return singbox.ParseSRSBytes(raw, entry, false, false, true)
	}
	if behavior, ok := mihomo.IsMRSBytes(raw); ok {
		if behavior != P.IPCIDR {
			return nil
		}
		_, err := mihomo.ParseMRSBytes(raw, entry, false, true)
		return err
	}
	return t.scanReader(bytes.NewReader(raw), entry)
}

func (t *ipTextIn) scanReader(r io.Reader, entry *lib.Entry) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, "//")
		line, _, _ = strings.Cut(line, "/*")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.ToLower(line)
		for _, prefix := range t.RemovePrefixesInLine {
			line = strings.TrimSpace(strings.TrimPrefix(line, strings.ToLower(strings.TrimSpace(prefix))))
		}
		for _, suffix := range t.RemoveSuffixesInLine {
			line = strings.TrimSpace(strings.TrimSuffix(line, strings.ToLower(strings.TrimSpace(suffix))))
		}
		if line == "" {
			continue
		}
		if err := entry.AddPrefix(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}
