package plaintext

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/Yuu518/sing-box-rules/lib"
)

func TestDomainAutoAllFormats(t *testing.T) {
	gfwEncoded := base64.StdEncoding.EncodeToString([]byte("[AutoProxy 0.2.9]\n! comment\n||gfw-auto.org\n@@||skip-white.org\n.gfw-dot.net\n"))
	singboxJSON := `{"version":4,"rules":[{"domain":["sb-exact.io"],"domain_suffix":["sb-suf.io"],"domain_keyword":["sbkw"],"domain_regex":["^sb-[0-9]+$"]}]}`
	clashYAML := "payload:\n  - 'clash-exact.dev'\n  - '+.clash-suf.dev'\n  - 'DOMAIN,clash-class.dev'\n  - 'DOMAIN-SUFFIX,clash-csuf.dev'\n  - 'IP-CIDR,1.1.1.0/24'\n"
	mixedText := `
# comment
// another comment
[Rule]
server=/dnsmasq.google.com/114.114.114.114
address=/dnsmasq-addr.example/0.0.0.0
DOMAIN,surge-exact.net
DOMAIN-SUFFIX,surge-suf.net
DOMAIN-KEYWORD,surgekw
DOMAIN-REGEX,^surge\..+$
IP-CIDR,10.0.0.0/8
.dot-suffix.org
+.plus-suffix.org
*.star-suffix.org
0.0.0.0 hosts-ad.example localhost
||adblock-dom.example^
@@||adblock-white.example^
domain:v2-suf.com
domain:v2-skip.com:@cn
full:v2-exact.com
keyword:v2kw
regexp:^v2\..+$
bare-domain.net
`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gfw":
			fmt.Fprint(w, gfwEncoded)
		case "/sb":
			fmt.Fprint(w, singboxJSON)
		case "/clash":
			fmt.Fprint(w, clashYAML)
		case "/mixed":
			fmt.Fprint(w, mixedText)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := lib.NewContainer()
	for _, tc := range []struct {
		url          string
		excludeAttrs []string
	}{
		{srv.URL + "/gfw", nil},
		{srv.URL + "/sb", nil},
		{srv.URL + "/clash", nil},
		{srv.URL + "/mixed", []string{"cn"}},
	} {
		rawArgs, _ := json.Marshal(map[string]any{
			"name":         "all",
			"uri":          tc.url,
			"excludeAttrs": tc.excludeAttrs,
		})
		conv, err := NewDomainAutoInFromBytes(lib.ActionAdd, rawArgs)
		if err != nil {
			t.Fatalf("NewDomainAutoInFromBytes(%s): %v", tc.url, err)
		}
		if _, err := conv.Input(c); err != nil {
			t.Fatalf("Input(%s): %v", tc.url, err)
		}
	}

	entry, ok := c.GetEntry("ALL")
	if !ok {
		t.Fatal("ALL entry missing")
	}
	domains, suffixes, keywords, regexes := entry.GetDomainRulesByType()

	for _, want := range []string{"sb-exact.io", "clash-exact.dev", "clash-class.dev", "surge-exact.net", "hosts-ad.example", "v2-exact.com"} {
		if !slices.Contains(domains, want) {
			t.Fatalf("expected domain %q in %v", want, domains)
		}
	}
	for _, want := range []string{"gfw-auto.org", "gfw-dot.net", "sb-suf.io", "clash-suf.dev", "clash-csuf.dev", "dnsmasq.google.com", "dnsmasq-addr.example", "surge-suf.net", "dot-suffix.org", "plus-suffix.org", "star-suffix.org", "adblock-dom.example", "v2-suf.com", "bare-domain.net"} {
		if !slices.Contains(suffixes, want) {
			t.Fatalf("expected suffix %q in %v", want, suffixes)
		}
	}
	for _, want := range []string{"sbkw", "surgekw", "v2kw"} {
		if !slices.Contains(keywords, want) {
			t.Fatalf("expected keyword %q in %v", want, keywords)
		}
	}
	for _, want := range []string{"^sb-[0-9]+$", `^surge\..+$`, `^v2\..+$`} {
		if !slices.Contains(regexes, want) {
			t.Fatalf("expected regex %q in %v", want, regexes)
		}
	}
	for _, forbidden := range []string{"skip-white.org", "adblock-white.example", "v2-skip.com", "localhost"} {
		if slices.Contains(domains, forbidden) || slices.Contains(suffixes, forbidden) {
			t.Fatalf("unexpected forbidden domain %q", forbidden)
		}
	}
}

func TestMihomoDomainIn(t *testing.T) {
	yamlData := "payload:\n  - 'exact.mihomo.dev'\n  - '+.suf.mihomo.dev'\n  - '.dot.mihomo.dev'\n  - 'DOMAIN,class-exact.mihomo.dev'\n  - 'DOMAIN-SUFFIX,class-suf.mihomo.dev'\n  - 'DOMAIN-KEYWORD,mhkw'\n  - 'DOMAIN-REGEX,^mh-[0-9]+$'\n  - 'IP-CIDR,1.1.1.0/24'\n"
	textData := "# comment\nplain-exact.mihomo.dev\n+.plain-suf.mihomo.dev\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/yaml":
			fmt.Fprint(w, yamlData)
		case "/text":
			fmt.Fprint(w, textData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := lib.NewContainer()
	for _, u := range []string{srv.URL + "/yaml", srv.URL + "/text"} {
		rawArgs, _ := json.Marshal(map[string]any{
			"name": "mh",
			"uri":  u,
		})
		conv, err := NewMihomoDomainInFromBytes(lib.ActionAdd, rawArgs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conv.Input(c); err != nil {
			t.Fatal(err)
		}
	}

	e, ok := c.GetEntry("MH")
	if !ok {
		t.Fatal("MH entry missing")
	}
	domains, suffixes, keywords, regexes := e.GetDomainRulesByType()
	for _, want := range []string{"exact.mihomo.dev", "class-exact.mihomo.dev", "plain-exact.mihomo.dev"} {
		if !slices.Contains(domains, want) {
			t.Fatalf("expected domain %q in %v", want, domains)
		}
	}
	for _, want := range []string{"suf.mihomo.dev", "dot.mihomo.dev", "class-suf.mihomo.dev", "plain-suf.mihomo.dev"} {
		if !slices.Contains(suffixes, want) {
			t.Fatalf("expected suffix %q in %v", want, suffixes)
		}
	}
	if !slices.Contains(keywords, "mhkw") || !slices.Contains(regexes, "^mh-[0-9]+$") {
		t.Fatalf("unexpected keywords=%v regexes=%v", keywords, regexes)
	}
}
