package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type buildOptions struct {
	RuleSetDir    string
	ReleaseDir    string
	WebDir        string
	OutDir        string
	ShardCount    int
	Repo          string
	RulesRepo     string
	SiteBranch    string
	ReleaseBranch string
	RulesBranch   string
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type ruleSetFile struct {
	Version int           `json:"version"`
	Rules   []ruleSetRule `json:"rules"`
}

type ruleSetRule struct {
	Domain        stringList `json:"domain"`
	DomainSuffix  stringList `json:"domain_suffix"`
	DomainKeyword stringList `json:"domain_keyword"`
	DomainRegex   stringList `json:"domain_regex"`
	IPCIDR        stringList `json:"ip_cidr"`
}

type entryData struct {
	name     string
	domains  map[string]struct{}
	suffixes map[string]struct{}
	keywords map[string]struct{}
	regexes  map[string]struct{}
	ipv4     map[netip.Prefix]struct{}
	ipv6     map[netip.Prefix]struct{}
	adguard  int
}

func newEntryData(name string) *entryData {
	return &entryData{
		name:     name,
		domains:  make(map[string]struct{}),
		suffixes: make(map[string]struct{}),
		keywords: make(map[string]struct{}),
		regexes:  make(map[string]struct{}),
		ipv4:     make(map[netip.Prefix]struct{}),
		ipv6:     make(map[netip.Prefix]struct{}),
	}
}

type manifestDoc struct {
	GeneratedAt   string          `json:"generatedAt"`
	ShardCount    int             `json:"shardCount"`
	Repo          string          `json:"repo"`
	RulesRepo     string          `json:"rulesRepo"`
	SiteBranch    string          `json:"siteBranch"`
	ReleaseBranch string          `json:"releaseBranch"`
	RulesBranch   string          `json:"rulesBranch"`
	Totals        manifestTotals  `json:"totals"`
	Entries       []manifestEntry `json:"entries"`
}

type manifestTotals struct {
	Entries        int `json:"entries"`
	DomainEntries  int `json:"domainEntries"`
	IPEntries      int `json:"ipEntries"`
	AdGuardEntries int `json:"adguardEntries"`
	DomainRules    int `json:"domainRules"`
	IPRanges       int `json:"ipRanges"`
	AdGuardRules   int `json:"adguardRules"`
}

type manifestEntry struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Domain  int    `json:"domain,omitempty"`
	Suffix  int    `json:"suffix,omitempty"`
	Keyword int    `json:"keyword,omitempty"`
	Regex   int    `json:"regex,omitempty"`
	IP      int    `json:"ip,omitempty"`
	AdGuard int    `json:"adguard,omitempty"`
}

type shardDoc struct {
	Exact  map[string][]int `json:"e,omitempty"`
	Suffix map[string][]int `json:"s,omitempty"`
}

type specialDoc struct {
	Keywords [][]any `json:"k"`
	Regexes  [][]any `json:"r"`
}

type ipv4Item struct {
	start uint32
	end   uint32
	cidr  string
	ids   []int
}

type ipv6Item struct {
	start string
	end   string
	cidr  string
	ids   []int
}

func main() {
	var opts buildOptions
	var serveAddr string
	var skipBuild bool

	flag.StringVar(&opts.RuleSetDir, "rule-set", "./rule_set", "directory containing rule_set_site and rule_set_ip")
	flag.StringVar(&opts.ReleaseDir, "release", "./release", "directory containing AdGuard plaintext release files")
	flag.StringVar(&opts.WebDir, "web", "./web", "directory containing static web UI assets")
	flag.StringVar(&opts.OutDir, "out", "./dist", "output directory for generated site and index")
	flag.IntVar(&opts.ShardCount, "shards", 64, "number of domain lookup shards (1-256)")
	flag.StringVar(&opts.Repo, "repo", "Yuu518/sing-box-rules", "primary GitHub repository")
	flag.StringVar(&opts.RulesRepo, "rules-repo", "Yuu518/Yuu-rules", "secondary rules GitHub repository")
	flag.StringVar(&opts.SiteBranch, "site-branch", "rule_set", "branch name for rule_set files")
	flag.StringVar(&opts.ReleaseBranch, "release-branch", "release", "branch name for release files")
	flag.StringVar(&opts.RulesBranch, "rules-branch", "rule-set", "branch name for secondary rules repo")
	flag.StringVar(&serveAddr, "serve", "", "serve generated site at address, e.g. 127.0.0.1:8080")
	flag.BoolVar(&skipBuild, "skip-build", false, "skip index generation when serving")
	flag.Parse()

	if !skipBuild {
		if err := buildIndex(opts); err != nil {
			log.Fatalf("build failed: %v", err)
		}
	}

	if serveAddr != "" {
		if err := serveStatic(opts.OutDir, opts.RuleSetDir, serveAddr); err != nil {
			log.Fatalf("serve failed: %v", err)
		}
	}
}

func buildIndex(opts buildOptions) error {
	if opts.ShardCount <= 0 {
		opts.ShardCount = 64
	}
	if opts.ShardCount > 256 {
		opts.ShardCount = 256
	}

	entries := make(map[string]*entryData)
	getEntry := func(name string) *entryData {
		key := strings.ToLower(strings.TrimSpace(name))
		e, ok := entries[key]
		if !ok {
			e = newEntryData(key)
			entries[key] = e
		}
		return e
	}

	siteDir := filepath.Join(opts.RuleSetDir, "rule_set_site")
	jsonSiteNames := make(map[string]struct{})
	if dirEntries, err := os.ReadDir(siteDir); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
				continue
			}
			base := strings.TrimSuffix(de.Name(), ".json")
			key := strings.ToLower(base)
			jsonSiteNames[key] = struct{}{}
			if err := loadDomainJSON(filepath.Join(siteDir, de.Name()), getEntry(key)); err != nil {
				return err
			}
		}
		for _, de := range dirEntries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".srs") {
				continue
			}
			base := strings.TrimSuffix(de.Name(), ".srs")
			key := strings.ToLower(base)
			if _, hasJSON := jsonSiteNames[key]; hasJSON {
				continue
			}
			count := countAdGuardRules(opts.ReleaseDir, key)
			if count == 0 {
				count = 1
			}
			getEntry(key).adguard = count
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	ipDir := filepath.Join(opts.RuleSetDir, "rule_set_ip")
	if dirEntries, err := os.ReadDir(ipDir); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
				continue
			}
			base := strings.TrimSuffix(de.Name(), ".json")
			if err := loadIPJSON(filepath.Join(ipDir, de.Name()), getEntry(base)); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	dataDir := filepath.Join(opts.OutDir, "data")
	shardsDir := filepath.Join(dataDir, "shards")
	ip4Dir := filepath.Join(dataDir, "ip4")
	ip6Dir := filepath.Join(dataDir, "ip6")
	if err := os.RemoveAll(dataDir); err != nil {
		return err
	}
	for _, dir := range []string{shardsDir, ip4Dir, ip6Dir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if opts.WebDir != "" {
		if err := copyWebAssets(opts.WebDir, opts.OutDir); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)

	shards := make([]shardDoc, opts.ShardCount)
	for i := range shards {
		shards[i] = shardDoc{
			Exact:  make(map[string][]int),
			Suffix: make(map[string][]int),
		}
	}

	keywordMap := make(map[string][]int)
	regexMap := make(map[string][]int)
	ipv4Map := make(map[string]*ipv4Item)
	ipv6Map := make(map[string]*ipv6Item)

	manifest := manifestDoc{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ShardCount:    opts.ShardCount,
		Repo:          opts.Repo,
		RulesRepo:     opts.RulesRepo,
		SiteBranch:    opts.SiteBranch,
		ReleaseBranch: opts.ReleaseBranch,
		RulesBranch:   opts.RulesBranch,
	}

	nextID := 0
	for _, name := range names {
		e := entries[name]
		domains := sortedKeys(e.domains)
		suffixes := sortedKeys(e.suffixes)
		keywords := sortedKeys(e.keywords)
		regexes := sortedKeys(e.regexes)
		v4Prefixes := sortedPrefixes(e.ipv4)
		v6Prefixes := sortedPrefixes(e.ipv6)

		domTotal := len(domains) + len(suffixes) + len(keywords) + len(regexes)
		ipTotal := len(v4Prefixes) + len(v6Prefixes)
		agTotal := e.adguard
		if domTotal == 0 && ipTotal == 0 && agTotal == 0 {
			continue
		}

		id := nextID
		nextID++

		manifest.Entries = append(manifest.Entries, manifestEntry{
			ID:      id,
			Name:    e.name,
			Domain:  len(domains),
			Suffix:  len(suffixes),
			Keyword: len(keywords),
			Regex:   len(regexes),
			IP:      ipTotal,
			AdGuard: agTotal,
		})

		manifest.Totals.Entries++
		if domTotal > 0 {
			manifest.Totals.DomainEntries++
			manifest.Totals.DomainRules += domTotal
		}
		if ipTotal > 0 {
			manifest.Totals.IPEntries++
			manifest.Totals.IPRanges += ipTotal
		}
		if agTotal > 0 {
			manifest.Totals.AdGuardEntries++
			manifest.Totals.AdGuardRules += agTotal
		}

		for _, d := range domains {
			idx := int(fnv1a32(d) % uint32(opts.ShardCount))
			shards[idx].Exact[d] = append(shards[idx].Exact[d], id)
		}
		for _, s := range suffixes {
			idx := int(fnv1a32(s) % uint32(opts.ShardCount))
			shards[idx].Suffix[s] = append(shards[idx].Suffix[s], id)
		}
		for _, k := range keywords {
			keywordMap[k] = append(keywordMap[k], id)
		}
		for _, r := range regexes {
			regexMap[r] = append(regexMap[r], id)
		}

		for _, p := range v4Prefixes {
			cidr := p.String()
			item, ok := ipv4Map[cidr]
			if !ok {
				start, end := prefixRange4(p)
				item = &ipv4Item{
					start: start,
					end:   end,
					cidr:  cidr,
				}
				ipv4Map[cidr] = item
			}
			item.ids = append(item.ids, id)
		}

		for _, p := range v6Prefixes {
			cidr := p.String()
			item, ok := ipv6Map[cidr]
			if !ok {
				start, end := prefixRange6(p)
				item = &ipv6Item{
					start: start,
					end:   end,
					cidr:  cidr,
				}
				ipv6Map[cidr] = item
			}
			item.ids = append(item.ids, id)
		}
	}

	if err := writeJSONFile(filepath.Join(dataDir, "manifest.json"), manifest); err != nil {
		return err
	}

	for i := range shards {
		filename := fmt.Sprintf("d_%02x.json", i)
		if err := writeJSONFile(filepath.Join(shardsDir, filename), shards[i]); err != nil {
			return err
		}
	}

	special := specialDoc{
		Keywords: mapToSortedTuples(keywordMap),
		Regexes:  mapToSortedTuples(regexMap),
	}
	if err := writeJSONFile(filepath.Join(dataDir, "special.json"), special); err != nil {
		return err
	}

	v4List := make([]*ipv4Item, 0, len(ipv4Map))
	for _, item := range ipv4Map {
		v4List = append(v4List, item)
	}
	slices.SortFunc(v4List, func(a, b *ipv4Item) int {
		if a.start != b.start {
			if a.start < b.start {
				return -1
			}
			return 1
		}
		if a.end != b.end {
			if a.end < b.end {
				return -1
			}
			return 1
		}
		return strings.Compare(a.cidr, b.cidr)
	})
	const ipChunkSize = 25000

	v4Index := make([][]any, 0, (len(v4List)+ipChunkSize-1)/ipChunkSize)
	for i := 0; i < len(v4List); i += ipChunkSize {
		endIdx := min(i+ipChunkSize, len(v4List))
		chunk := v4List[i:endIdx]
		rows := make([][]any, 0, len(chunk))
		minStart := chunk[0].start
		maxEnd := chunk[0].end
		for _, item := range chunk {
			if item.end > maxEnd {
				maxEnd = item.end
			}
			rows = append(rows, []any{item.start, item.end, item.cidr, item.ids})
		}
		file := fmt.Sprintf("%02d.json", len(v4Index))
		if err := writeJSONFile(filepath.Join(ip4Dir, file), rows); err != nil {
			return err
		}
		v4Index = append(v4Index, []any{minStart, maxEnd, file})
	}
	if err := writeJSONFile(filepath.Join(ip4Dir, "index.json"), v4Index); err != nil {
		return err
	}

	v6List := make([]*ipv6Item, 0, len(ipv6Map))
	for _, item := range ipv6Map {
		v6List = append(v6List, item)
	}
	slices.SortFunc(v6List, func(a, b *ipv6Item) int {
		if a.start != b.start {
			return strings.Compare(a.start, b.start)
		}
		if a.end != b.end {
			return strings.Compare(a.end, b.end)
		}
		return strings.Compare(a.cidr, b.cidr)
	})
	v6Index := make([][]any, 0, (len(v6List)+ipChunkSize-1)/ipChunkSize)
	for i := 0; i < len(v6List); i += ipChunkSize {
		endIdx := min(i+ipChunkSize, len(v6List))
		chunk := v6List[i:endIdx]
		rows := make([][]any, 0, len(chunk))
		minStart := chunk[0].start
		maxEnd := chunk[0].end
		for _, item := range chunk {
			if item.end > maxEnd {
				maxEnd = item.end
			}
			rows = append(rows, []any{item.start, item.end, item.cidr, item.ids})
		}
		file := fmt.Sprintf("%02d.json", len(v6Index))
		if err := writeJSONFile(filepath.Join(ip6Dir, file), rows); err != nil {
			return err
		}
		v6Index = append(v6Index, []any{minStart, maxEnd, file})
	}
	if err := writeJSONFile(filepath.Join(ip6Dir, "index.json"), v6Index); err != nil {
		return err
	}

	log.Printf("generated index (%d entries, %d shards) --> %s", manifest.Totals.Entries, opts.ShardCount, opts.OutDir)
	return nil
}

func loadDomainJSON(path string, e *entryData) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc ruleSetFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range doc.Rules {
		for _, v := range r.Domain {
			v = normalizeDomain(v)
			if v != "" {
				e.domains[v] = struct{}{}
			}
		}
		for _, v := range r.DomainSuffix {
			v = normalizeDomain(v)
			if v != "" {
				e.suffixes[v] = struct{}{}
			}
		}
		for _, v := range r.DomainKeyword {
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "" {
				e.keywords[v] = struct{}{}
			}
		}
		for _, v := range r.DomainRegex {
			v = strings.TrimSpace(v)
			if v != "" {
				e.regexes[v] = struct{}{}
			}
		}
	}
	return nil
}

func loadIPJSON(path string, e *entryData) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc ruleSetFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range doc.Rules {
		for _, v := range r.IPCIDR {
			p, ok := parsePrefix(v)
			if !ok {
				continue
			}
			if p.Addr().Is4() {
				e.ipv4[p] = struct{}{}
			} else {
				e.ipv6[p] = struct{}{}
			}
		}
	}
	return nil
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	return s
}

func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func countAdGuardRules(releaseDir, name string) int {
	if releaseDir == "" {
		return 0
	}
	candidates := adguardReleaseCandidates(name)
	for _, rel := range candidates {
		path := filepath.Join(releaseDir, rel)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		count := 0
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !isAdGuardRuleLine(line) {
				continue
			}
			count++
		}
		_ = f.Close()
		if count > 0 {
			return count
		}
	}
	return 0
}

func adguardReleaseCandidates(name string) []string {
	switch name {
	case "category-ads-all-adguard":
		return []string{"reject-list-adguard.txt", name + ".txt"}
	case "awavenue-ads":
		return []string{"awavenue-ads-adguard.txt", name + ".txt"}
	default:
		return []string{name + "-adguard.txt", name + ".txt"}
	}
}

func isAdGuardRuleLine(line string) bool {
	if line == "" {
		return false
	}
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return false
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return false
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") || strings.Contains(line, "#%#") {
		return false
	}
	return true
}

func prefixRange4(p netip.Prefix) (uint32, uint32) {
	p = p.Masked()
	addr := p.Addr().As4()
	start := binary.BigEndian.Uint32(addr[:])
	bits := p.Bits()
	var hostMask uint32
	if bits == 0 {
		hostMask = ^uint32(0)
	} else if bits < 32 {
		hostMask = (uint32(1) << (32 - bits)) - 1
	}
	return start, start | hostMask
}

func prefixRange6(p netip.Prefix) (string, string) {
	p = p.Masked()
	start := p.Addr().As16()
	end := start
	bits := p.Bits()
	for i := bits; i < 128; i++ {
		end[i/8] |= 1 << (7 - uint(i%8))
	}
	return hex.EncodeToString(start[:]), hex.EncodeToString(end[:])
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedPrefixes(m map[netip.Prefix]struct{}) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		if a.Bits() < b.Bits() {
			return -1
		}
		if a.Bits() > b.Bits() {
			return 1
		}
		return 0
	})
	return out
}

func fnv1a32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

func mapToSortedTuples(m map[string][]int) [][]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([][]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, []any{k, m[k]})
	}
	return out
}

func writeJSONFile(path string, v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0644)
}

func copyWebAssets(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return os.WriteFile(target, content, 0644)
	})
}

func serveStatic(outDir, ruleSetDir, addr string) error {
	mux := http.NewServeMux()
	if ruleSetDir != "" {
		if info, err := os.Stat(ruleSetDir); err == nil && info.IsDir() {
			mux.Handle("/rule_set/", http.StripPrefix("/rule_set/", noCacheHandler(http.FileServer(http.Dir(ruleSetDir)))))
		}
	}
	mux.Handle("/", noCacheHandler(http.FileServer(http.Dir(outDir))))
	log.Printf("serving %s on http://%s", outDir, addr)
	return http.ListenAndServe(addr, mux)
}

func noCacheHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
