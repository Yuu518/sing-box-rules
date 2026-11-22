package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildIndex(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "rule_set", "rule_set_site")
	ipDir := filepath.Join(root, "rule_set", "rule_set_ip")
	releaseDir := filepath.Join(root, "release")
	webDir := filepath.Join(root, "web")
	outDir := filepath.Join(root, "dist")

	for _, d := range []string{siteDir, ipDir, releaseDir, webDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html></html>"), 0644); err != nil {
		t.Fatal(err)
	}

	youtubeJSON := `{"version":4,"rules":[{"domain":"yt3.googleusercontent.com","domain_suffix":["youtube.com","googlevideo.com"],"domain_keyword":"ytimg","domain_regex":"^r\\d+---sn"}]}`
	if err := os.WriteFile(filepath.Join(siteDir, "youtube.json"), []byte(youtubeJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "youtube.srs"), []byte("srs"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "category-ads-all-adguard.srs"), []byte("srs"), 0644); err != nil {
		t.Fatal(err)
	}

	cnIPJSON := `{"version":4,"rules":[{"ip_cidr":["1.0.1.0/24","2001:67c:4e8::/48"]}]}`
	if err := os.WriteFile(filepath.Join(ipDir, "cn.json"), []byte(cnIPJSON), 0644); err != nil {
		t.Fatal(err)
	}

	adguardTxt := "! Title: Test\n# Comment\n[Adblock Plus 2.0]\n||ads.example.com^\n||tracker.example.com^\nexample.com##.ad\n"
	if err := os.WriteFile(filepath.Join(releaseDir, "reject-list-adguard.txt"), []byte(adguardTxt), 0644); err != nil {
		t.Fatal(err)
	}

	err := buildIndex(buildOptions{
		RuleSetDir:    filepath.Join(root, "rule_set"),
		ReleaseDir:    releaseDir,
		WebDir:        webDir,
		OutDir:        outDir,
		ShardCount:    16,
		Repo:          "Yuu518/sing-box-rules",
		RulesRepo:     "Yuu518/Yuu-rules",
		SiteBranch:    "rule_set",
		ReleaseBranch: "release",
		RulesBranch:   "rule-set",
	})
	if err != nil {
		t.Fatalf("buildIndex failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outDir, "index.html")); err != nil {
		t.Fatalf("index.html missing: %v", err)
	}

	rawManifest, err := os.ReadFile(filepath.Join(outDir, "data", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifestDoc
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.Totals.Entries != 3 || m.Totals.DomainEntries != 1 || m.Totals.IPEntries != 1 || m.Totals.AdGuardEntries != 1 {
		t.Fatalf("unexpected totals: %+v", m.Totals)
	}
	if m.Totals.AdGuardRules != 2 {
		t.Fatalf("expected 2 adguard rules, got %d", m.Totals.AdGuardRules)
	}

	shardIdx := int(fnv1a32("youtube.com") % 16)
	rawShard, err := os.ReadFile(filepath.Join(outDir, "data", "shards", fmt.Sprintf("d_%02x.json", shardIdx)))
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	var sd shardDoc
	if err := json.Unmarshal(rawShard, &sd); err != nil {
		t.Fatalf("unmarshal shard: %v", err)
	}
	if len(sd.Suffix["youtube.com"]) != 1 {
		t.Fatalf("expected youtube.com in shard %d, got %+v", shardIdx, sd.Suffix)
	}

	rawV4, err := os.ReadFile(filepath.Join(outDir, "data", "ip_v4.json"))
	if err != nil {
		t.Fatalf("read ip_v4.json: %v", err)
	}
	var v4 [][]any
	if err := json.Unmarshal(rawV4, &v4); err != nil {
		t.Fatalf("unmarshal ip_v4.json: %v", err)
	}
	if len(v4) != 1 || v4[0][2] != "1.0.1.0/24" {
		t.Fatalf("unexpected ip_v4.json: %+v", v4)
	}

	rawV6, err := os.ReadFile(filepath.Join(outDir, "data", "ip_v6.json"))
	if err != nil {
		t.Fatalf("read ip_v6.json: %v", err)
	}
	var v6 [][]any
	if err := json.Unmarshal(rawV6, &v6); err != nil {
		t.Fatalf("unmarshal ip_v6.json: %v", err)
	}
	if len(v6) != 1 || v6[0][0] != "2001067c04e800000000000000000000" || v6[0][1] != "2001067c04e8ffffffffffffffffffff" {
		t.Fatalf("unexpected ip_v6.json: %+v", v6)
	}
}

func TestPrefixRangeBounds(t *testing.T) {
	s4, e4 := prefixRange4(netip.MustParsePrefix("0.0.0.0/0"))
	if s4 != 0 || e4 != ^uint32(0) {
		t.Fatalf("unexpected /0 v4 bounds: %d..%d", s4, e4)
	}
	s4, e4 = prefixRange4(netip.MustParsePrefix("192.168.1.5/32"))
	if s4 != e4 {
		t.Fatalf("expected equal /32 bounds, got %d..%d", s4, e4)
	}
	s6, e6 := prefixRange6(netip.MustParsePrefix("::1/128"))
	if s6 != e6 || s6 != "00000000000000000000000000000001" {
		t.Fatalf("unexpected /128 v6 bounds: %s..%s", s6, e6)
	}
}
