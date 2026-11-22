package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestDefaultConfigJSONValid(t *testing.T) {
	inst, err := lib.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.InitConfig("./config.json"); err != nil {
		t.Fatalf("default config.json failed to initialize: %v", err)
	}
}

func TestEndToEndPipeline(t *testing.T) {
	tmp := t.TempDir()

	communityDir := filepath.Join(tmp, "community", "data")
	srcDir := filepath.Join(tmp, "src")
	geoipDir := filepath.Join(tmp, "geoip", "text")
	if err := os.MkdirAll(communityDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(geoipDir, 0755); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, filepath.Join(communityDir, "36kr"), "36kr.com\nad.36kr.com @ads\n")
	writeTestFile(t, filepath.Join(communityDir, "pikpak"), "mypikpak.com\n")
	writeTestFile(t, filepath.Join(communityDir, "cn"), "old-cn.example\n")
	writeTestFile(t, filepath.Join(srcDir, "direct.txt"), "skland.com\n")
	writeTestFile(t, filepath.Join(srcDir, "direct-need-to-remove.txt"), "remove-me.cn\n")
	writeTestFile(t, filepath.Join(srcDir, "proxy.txt"), "supertop.co\n")
	writeTestFile(t, filepath.Join(srcDir, "proxy-need-to-remove.txt"), "remove-proxy.com\n")
	writeTestFile(t, filepath.Join(srcDir, "reject.txt"), "ad.bad.com\n")
	writeTestFile(t, filepath.Join(srcDir, "reject-need-to-remove.txt"), "keep.good.com\n")
	writeTestFile(t, filepath.Join(srcDir, "reject-need-to-remove-adguard.txt"), "||keep.good.com^\n")
	writeTestFile(t, filepath.Join(geoipDir, "telegram.txt"), "91.108.4.0/22\n2001:67c:4e8::/48\n")

	gfwRaw := "[AutoProxy 0.2.9]\n! comment\n||blocked.org\n@@||whitelisted.org\n.gfw-site.net\n|https://remove-proxy.com/path\n"
	gfwEncoded := base64.StdEncoding.EncodeToString([]byte(gfwRaw))

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gfwlist.txt":
			fmt.Fprint(w, gfwEncoded)
		case "/google.china.conf":
			fmt.Fprint(w, "server=/google.com/114.114.114.114\nserver=/bad.cn/114.114.114.114\n")
		case "/custom-proxy.txt":
			fmt.Fprint(w, "domain:proxy-ok.com\ndomain:cn-skip.com:@cn\nfull:exact.proxy.io\nkeyword:proxykw\nregexp:^ad\\..+$\n")
		case "/adrules.txt":
			fmt.Fprint(w, "domain:tracker.example\ndomain:keep.good.com\nfull:full-ad.example\nregexp:^ads-[0-9]+\\.test$\n")
		case "/adguard.txt":
			fmt.Fprint(w, "[Adblock Plus 2.0]\n! Title: Test\n! Total count: 2\n# comment\nexample.com##.ad-banner\n||tracker.example^\n||keep.good.com^\n")
		case "/cdn.conf":
			fmt.Fprint(w, "# comment\n.first-skipped.cdn\n.fastly.net\nDOMAIN,exact.cdn.net\nDOMAIN-SUFFIX,msedge.net\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer httpSrv.Close()

	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rules-bucket" && r.URL.Query().Get("list-type") == "2" {
			fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>cn-only</Key></Contents><Contents><Key>pcdn-cn</Key></Contents></ListBucketResult>`)
			return
		}
		switch r.URL.Path {
		case "/rules-bucket/cn-only":
			fmt.Fprint(w, "baidu.com\nremove-me.cn\nxn--fiqs8s\n")
		case "/rules-bucket/pcdn-cn":
			fmt.Fprint(w, "pcdn.example.cn\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer s3Srv.Close()

	t.Setenv("R2_ACCESS_KEY_ID", "test-ak")
	t.Setenv("R2_SECRET_ACCESS_KEY", "test-sk")
	t.Setenv("R2_BUCKET_NAME", "rules-bucket")
	t.Setenv("S3_ENDPOINT", s3Srv.URL)

	outSingboxSite := filepath.Join(tmp, "rule_set", "rule_set_site")
	outSingboxIP := filepath.Join(tmp, "rule_set", "rule_set_ip")
	outSurgeSite := filepath.Join(tmp, "rule-set", "surge", "geosite")
	outSurgeIP := filepath.Join(tmp, "rule-set", "surge", "geoip")
	outMihomoSite := filepath.Join(tmp, "rule-set", "mihomo", "geosite")
	outMihomoIP := filepath.Join(tmp, "rule-set", "mihomo", "geoip")
	outTextSite := filepath.Join(tmp, "rule-set", "text", "geosite")
	outTextIP := filepath.Join(tmp, "rule-set", "text", "geoip")
	outPublish := filepath.Join(tmp, "publish")

	cfg := fmt.Sprintf(`{
  "input": [
    { "type": "v2flyDomain", "action": "add", "args": { "inputDir": %q } },
    { "type": "v2flyDomain", "action": "replace", "args": { "inputDir": "s3:///" } },
    { "type": "cutter", "action": "remove", "args": { "kind": "domain", "wantedList": ["cn", "geolocation-!cn", "category-ads-all"] } },
    { "type": "domain", "action": "add", "args": { "name": "cn", "uri": "s3:///cn-only" } },
    { "type": "domain", "action": "add", "args": { "name": "cn", "uri": %q } },
    { "type": "domain", "action": "remove", "args": { "name": "cn", "uri": %q } },
    { "type": "domainFilter", "action": "add", "args": { "wantedList": ["cn"], "validDomainOnly": true } },
    { "type": "domain", "action": "add", "args": { "names": ["geolocation-!cn", "gfw"], "uri": %q } },
    { "type": "domain", "action": "add", "args": { "name": "geolocation-!cn", "uri": %q } },
    { "type": "domain", "action": "add", "args": { "name": "geolocation-!cn", "uri": %q, "excludeAttrs": ["cn"], "onlyRuleTypes": ["domain_suffix"] } },
    { "type": "domain", "action": "add", "args": { "name": "geolocation-!cn", "uri": %q } },
    { "type": "domain", "action": "remove", "args": { "name": "geolocation-!cn", "uri": %q } },
    { "type": "domainFilter", "action": "add", "args": { "wantedList": ["geolocation-!cn"], "validDomainOnly": true, "excludeSuffixes": [".cn"] } },
    { "type": "domain", "action": "add", "args": { "name": "geolocation-!cn", "uri": %q, "excludeAttrs": ["cn"], "onlyRuleTypes": ["domain", "domain_keyword", "domain_regex"] } },
    { "type": "domain", "action": "add", "args": { "name": "category-ads-all", "uri": %q } },
    { "type": "domain", "action": "add", "args": { "name": "category-ads-all", "uri": %q } },
    { "type": "domain", "action": "remove", "args": { "name": "category-ads-all", "uri": %q } },
    { "type": "adguard", "action": "add", "args": { "name": "category-ads-all-adguard", "uri": %q } },
    { "type": "adguard", "action": "remove", "args": { "name": "category-ads-all-adguard", "uri": %q } },
    { "type": "domain", "action": "add", "args": { "name": "category-cdn-!cn", "uri": %q, "skipEntries": 1 } },
    { "type": "domain", "action": "add", "args": { "name": "pikpak", "rules": ["pikpak.site"] } },
    { "type": "domain", "action": "add", "args": { "name": "download-!cn", "rules": ["include:pikpak"] } },
    { "type": "v2flyResolve", "action": "add", "args": { "generateAttrEntries": true } },
    { "type": "ip", "action": "add", "args": { "inputDir": %q } }
  ],
  "output": [
    { "type": "singboxDomain", "action": "output", "args": { "outputDir": %q, "version": 4 } },
    { "type": "singboxIP", "action": "output", "args": { "outputDir": %q, "version": 4 } },
    { "type": "singboxAdGuard", "action": "output", "args": { "outputDir": %q, "version": 4, "wantedList": ["category-ads-all-adguard"] } },
    { "type": "surgeDomain", "action": "output", "args": { "outputDir": %q } },
    { "type": "surgeIP", "action": "output", "args": { "outputDir": %q } },
    { "type": "mihomoDomain", "action": "output", "args": { "outputDir": %q } },
    { "type": "mihomoIP", "action": "output", "args": { "outputDir": %q } },
    { "type": "textDomain", "action": "output", "args": { "outputDir": %q, "format": "prefixed" } },
    { "type": "textIP", "action": "output", "args": { "outputDir": %q } },
    { "type": "textDomain", "action": "output", "args": { "outputDir": %q, "outputName": "direct-list.txt", "wantedList": ["cn"], "format": "v2fly" } },
    { "type": "textDomain", "action": "output", "args": { "outputDir": %q, "outputName": "direct-tld-list.txt", "wantedList": ["cn"], "format": "tld", "excludeRuleTypes": ["domain", "domain_keyword", "domain_regex"] } },
    { "type": "textDomain", "action": "output", "args": { "outputDir": %q, "outputName": "hosts", "wantedList": ["category-ads-all"], "format": "v2fly", "excludeRuleTypes": ["domain_regex"], "addPrefixInLine": "0.0.0.0 " } },
    { "type": "textAdGuard", "action": "output", "args": { "outputDir": %q, "outputName": "reject-list-adguard.txt", "wantedList": ["category-ads-all-adguard"] } }
  ]
}`,
		communityDir,
		filepath.Join(srcDir, "direct.txt"),
		filepath.Join(srcDir, "direct-need-to-remove.txt"),
		httpSrv.URL+"/gfwlist.txt",
		httpSrv.URL+"/google.china.conf",
		httpSrv.URL+"/custom-proxy.txt",
		filepath.Join(srcDir, "proxy.txt"),
		filepath.Join(srcDir, "proxy-need-to-remove.txt"),
		httpSrv.URL+"/custom-proxy.txt",
		httpSrv.URL+"/adrules.txt",
		filepath.Join(srcDir, "reject.txt"),
		filepath.Join(srcDir, "reject-need-to-remove.txt"),
		httpSrv.URL+"/adguard.txt",
		filepath.Join(srcDir, "reject-need-to-remove-adguard.txt"),
		httpSrv.URL+"/cdn.conf",
		geoipDir,
		outSingboxSite,
		outSingboxIP,
		outSingboxSite,
		outSurgeSite,
		outSurgeIP,
		outMihomoSite,
		outMihomoIP,
		outTextSite,
		outTextIP,
		outPublish,
		outPublish,
		outPublish,
		outPublish,
	)

	inst, err := lib.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.InitConfigFromBytes([]byte(cfg)); err != nil {
		t.Fatalf("InitConfigFromBytes error: %v", err)
	}
	if err := inst.Run(); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	assertSRSVersion(t, filepath.Join(outSingboxSite, "geolocation-!cn.srs"), constant.RuleSetVersion4)
	assertSRSVersion(t, filepath.Join(outSingboxSite, "36kr@ads.srs"), constant.RuleSetVersion4)
	assertSRSVersion(t, filepath.Join(outSingboxSite, "download-!cn.srs"), constant.RuleSetVersion4)
	assertSRSVersion(t, filepath.Join(outSingboxSite, "pcdn-cn.srs"), constant.RuleSetVersion4)
	assertSRSVersion(t, filepath.Join(outSingboxSite, "category-ads-all-adguard.srs"), constant.RuleSetVersion4)
	assertSRSVersion(t, filepath.Join(outSingboxIP, "telegram.srs"), constant.RuleSetVersion4)

	proxyJSONBytes, err := os.ReadFile(filepath.Join(outSingboxSite, "geolocation-!cn.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsedProxy option.PlainRuleSetCompat
	if err := json.Unmarshal(proxyJSONBytes, &parsedProxy); err != nil {
		t.Fatal(err)
	}
	if parsedProxy.Version != constant.RuleSetVersion4 {
		t.Fatalf("expected sing-box JSON version 4, got %d", parsedProxy.Version)
	}
	proxyJSONStr := string(proxyJSONBytes)
	for _, mustHave := range []string{"blocked.org", "google.com", "proxy-ok.com", "exact.proxy.io", "proxykw", "supertop.co"} {
		if !strings.Contains(proxyJSONStr, mustHave) {
			t.Fatalf("geolocation-!cn.json missing %q: %s", mustHave, proxyJSONStr)
		}
	}
	for _, mustNotHave := range []string{"bad.cn", "cn-skip.com", "remove-proxy.com", "whitelisted.org"} {
		if strings.Contains(proxyJSONStr, mustNotHave) {
			t.Fatalf("geolocation-!cn.json should not contain %q", mustNotHave)
		}
	}

	surgeSiteContent := mustReadString(t, filepath.Join(outSurgeSite, "category-cdn-!cn.list"))
	if !strings.Contains(surgeSiteContent, "DOMAIN,exact.cdn.net\n") || !strings.Contains(surgeSiteContent, "DOMAIN-SUFFIX,fastly.net\n") || !strings.Contains(surgeSiteContent, "DOMAIN-SUFFIX,msedge.net\n") {
		t.Fatalf("unexpected surgeSite content: %s", surgeSiteContent)
	}
	if strings.Contains(surgeSiteContent, "first-skipped.cdn") {
		t.Fatalf("skipEntries did not skip first entry: %s", surgeSiteContent)
	}

	surgeIPContent := mustReadString(t, filepath.Join(outSurgeIP, "telegram.list"))
	if !strings.Contains(surgeIPContent, "IP-CIDR,91.108.4.0/22\n") || !strings.Contains(surgeIPContent, "IP-CIDR6,2001:67c:4e8::/48\n") {
		t.Fatalf("unexpected surgeIP content: %s", surgeIPContent)
	}

	mihomoYAML := mustReadString(t, filepath.Join(outMihomoSite, "download-!cn.yaml"))
	if !strings.Contains(mihomoYAML, "'+.mypikpak.com'") || !strings.Contains(mihomoYAML, "'+.pikpak.site'") {
		t.Fatalf("unexpected mihomoSite yaml: %s", mihomoYAML)
	}
	assertFileNonEmpty(t, filepath.Join(outMihomoSite, "download-!cn.mrs"))
	assertFileNonEmpty(t, filepath.Join(outMihomoIP, "telegram.yaml"))
	assertFileNonEmpty(t, filepath.Join(outMihomoIP, "telegram.mrs"))

	textSiteContent := mustReadString(t, filepath.Join(outTextSite, "category-cdn-!cn.txt"))
	if !strings.Contains(textSiteContent, "full:exact.cdn.net\n") || !strings.Contains(textSiteContent, "domain:fastly.net\n") {
		t.Fatalf("unexpected prefixed textSite content: %s", textSiteContent)
	}

	directList := mustReadString(t, filepath.Join(outPublish, "direct-list.txt"))
	if !strings.Contains(directList, "baidu.com\n") || !strings.Contains(directList, "skland.com\n") || strings.Contains(directList, "remove-me.cn") || strings.Contains(directList, "old-cn.example") {
		t.Fatalf("unexpected direct-list.txt: %s", directList)
	}

	directTLD := mustReadString(t, filepath.Join(outPublish, "direct-tld-list.txt"))
	if strings.TrimSpace(directTLD) != "xn--fiqs8s" {
		t.Fatalf("unexpected direct-tld-list.txt: %q", directTLD)
	}

	hostsContent := mustReadString(t, filepath.Join(outPublish, "hosts"))
	if !strings.Contains(hostsContent, "0.0.0.0 tracker.example\n") || strings.Contains(hostsContent, "regexp:") || strings.Contains(hostsContent, "keep.good.com") {
		t.Fatalf("unexpected hosts: %s", hostsContent)
	}

	adguardContent := mustReadString(t, filepath.Join(outPublish, "reject-list-adguard.txt"))
	if strings.TrimSpace(adguardContent) != "||tracker.example^" {
		t.Fatalf("unexpected reject-list-adguard.txt: %q", adguardContent)
	}

	verifyBinaryInputs(t,
		filepath.Join(outSingboxSite, "geolocation-!cn.srs"),
		filepath.Join(outSingboxSite, "category-ads-all-adguard.srs"),
		filepath.Join(outSingboxIP, "telegram.srs"),
		filepath.Join(outMihomoSite, "download-!cn.mrs"),
		filepath.Join(outMihomoIP, "telegram.mrs"),
	)
}

func verifyBinaryInputs(t *testing.T, siteSRS, adguardSRS, ipSRS, siteMRS, ipMRS string) {
	t.Helper()

	cfg := fmt.Sprintf(`{
  "input": [
    { "type": "domain", "action": "add", "args": { "name": "auto-srs-dom", "uri": %q } },
    { "type": "domain", "action": "add", "args": { "name": "auto-mrs-dom", "uri": %q } },
    { "type": "ip", "action": "add", "args": { "name": "auto-srs-ip", "uri": %q } },
    { "type": "ip", "action": "add", "args": { "name": "auto-mrs-ip", "uri": %q } },
    { "type": "singboxSRS", "action": "add", "args": { "name": "direct-srs", "uri": %q } },
    { "type": "singboxSRS", "action": "add", "args": { "name": "direct-srs-ag", "uri": %q } },
    { "type": "singboxSRS", "action": "add", "args": { "name": "direct-srs-ip", "uri": %q } },
    { "type": "mihomoMRS", "action": "add", "args": { "name": "direct-mrs-dom", "uri": %q } },
    { "type": "mihomoMRS", "action": "add", "args": { "name": "direct-mrs-ip", "uri": %q } }
  ]
}`, siteSRS, siteMRS, ipSRS, ipMRS, siteSRS, adguardSRS, ipSRS, siteMRS, ipMRS)

	inst, err := lib.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.InitConfigFromBytes([]byte(cfg)); err != nil {
		t.Fatalf("binary config init failed: %v", err)
	}
	c := lib.NewContainer()
	if err := inst.RunInput(c); err != nil {
		t.Fatalf("binary RunInput failed: %v", err)
	}

	for _, name := range []string{"auto-srs-dom", "direct-srs"} {
		e, ok := c.GetEntry(name)
		if !ok {
			t.Fatalf("missing entry %s", name)
		}
		domains, suffixes, keywords, regexes := e.GetDomainRulesByType()
		if !containsStr(domains, "exact.proxy.io") || !containsStr(suffixes, "google.com") || !containsStr(keywords, "proxykw") || len(regexes) == 0 {
			t.Fatalf("entry %s unexpected rules: d=%v s=%v k=%v r=%v", name, domains, suffixes, keywords, regexes)
		}
	}

	for _, name := range []string{"auto-mrs-dom", "direct-mrs-dom"} {
		e, ok := c.GetEntry(name)
		if !ok {
			t.Fatalf("missing entry %s", name)
		}
		_, suffixes, _, _ := e.GetDomainRulesByType()
		if !containsStr(suffixes, "mypikpak.com") || !containsStr(suffixes, "pikpak.site") {
			t.Fatalf("entry %s unexpected mrs suffixes: %v", name, suffixes)
		}
	}

	agEntry, ok := c.GetEntry("direct-srs-ag")
	if !ok || !agEntry.HasAdGuardRules() {
		t.Fatalf("expected adguard rules recovered from srs")
	}

	for _, name := range []string{"auto-srs-ip", "auto-mrs-ip", "direct-srs-ip", "direct-mrs-ip"} {
		e, ok := c.GetEntry(name)
		if !ok {
			t.Fatalf("missing ip entry %s", name)
		}
		cidrs, err := e.MarshalIPText()
		if err != nil {
			t.Fatal(err)
		}
		if !containsStr(cidrs, "91.108.4.0/22") || !containsStr(cidrs, "2001:67c:4e8::/48") {
			t.Fatalf("entry %s unexpected cidrs: %v", name, cidrs)
		}
	}
}

func containsStr(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func writeTestFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func mustReadString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertFileNonEmpty(t *testing.T, p string) {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("expected file %s: %v", p, err)
	}
	if info.Size() == 0 {
		t.Fatalf("file %s is empty", p)
	}
}

func assertSRSVersion(t *testing.T, p string, wantVersion uint8) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer f.Close()
	compat, err := srs.Read(f, true)
	if err != nil {
		t.Fatalf("srs.Read(%s) failed: %v", p, err)
	}
	if compat.Version != wantVersion {
		t.Fatalf("srs %s version = %d, want %d", p, compat.Version, wantVersion)
	}
}
