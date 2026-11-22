package lib

import (
	"net/netip"
	"slices"
	"strings"

	"go4.org/netipx"
)

type DomainRule struct {
	Type  RuleType
	Value string
	Attrs []string
}

type IncludeRef struct {
	Target string
	Attr   string
	Negate bool
}

type domainRuleKey struct {
	ruleType RuleType
	value    string
}

type Entry struct {
	name string

	domainRules map[domainRuleKey]*DomainRule
	includes    map[IncludeRef]struct{}

	adguardRules map[string]struct{}

	ipv4Builder *netipx.IPSetBuilder
	ipv4Set     *netipx.IPSet
	ipv6Builder *netipx.IPSetBuilder
	ipv6Set     *netipx.IPSet
}

func NewEntry(name string) *Entry {
	return &Entry{
		name: strings.ToUpper(strings.TrimSpace(name)),
	}
}

func (e *Entry) GetName() string {
	return e.name
}

func (e *Entry) GetLowerName() string {
	return strings.ToLower(e.name)
}

func normalizeDomainRuleValue(ruleType RuleType, value string) string {
	value = strings.TrimSpace(value)
	if ruleType != RuleTypeDomainRegex {
		value = strings.ToLower(value)
	}
	return value
}

func normalizeAttrs(attrs []string) []string {
	if len(attrs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(attrs))
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		a = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a, "@")))
		if a == "" {
			continue
		}
		if _, ok := seen[a]; !ok {
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

func (e *Entry) AddDomainRule(rule DomainRule) {
	val := normalizeDomainRuleValue(rule.Type, rule.Value)
	if val == "" {
		return
	}
	if e.domainRules == nil {
		e.domainRules = make(map[domainRuleKey]*DomainRule)
	}
	key := domainRuleKey{ruleType: rule.Type, value: val}
	attrs := normalizeAttrs(rule.Attrs)
	if existing, ok := e.domainRules[key]; ok {
		if len(attrs) > 0 {
			existing.Attrs = normalizeAttrs(append(existing.Attrs, attrs...))
		}
		return
	}
	e.domainRules[key] = &DomainRule{
		Type:  rule.Type,
		Value: val,
		Attrs: attrs,
	}
}

func (e *Entry) RemoveDomainRule(ruleType RuleType, value string) {
	if len(e.domainRules) == 0 {
		return
	}
	val := normalizeDomainRuleValue(ruleType, value)
	delete(e.domainRules, domainRuleKey{ruleType: ruleType, value: val})
}

func (e *Entry) RemoveDomainValueAllTypes(value string) {
	if len(e.domainRules) == 0 {
		return
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	trimmed := strings.TrimSpace(value)
	delete(e.domainRules, domainRuleKey{ruleType: RuleTypeDomain, value: lower})
	delete(e.domainRules, domainRuleKey{ruleType: RuleTypeDomainSuffix, value: lower})
	delete(e.domainRules, domainRuleKey{ruleType: RuleTypeDomainKeyword, value: lower})
	delete(e.domainRules, domainRuleKey{ruleType: RuleTypeDomainRegex, value: trimmed})
}

func (e *Entry) AddInclude(ref IncludeRef) {
	ref.Target = strings.ToUpper(strings.TrimSpace(ref.Target))
	ref.Attr = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(ref.Attr, "@")))
	if ref.Target == "" {
		return
	}
	if e.includes == nil {
		e.includes = make(map[IncludeRef]struct{})
	}
	e.includes[ref] = struct{}{}
}

func (e *Entry) HasDomainRules() bool {
	return len(e.domainRules) > 0
}

func (e *Entry) HasIncludes() bool {
	return len(e.includes) > 0
}

func (e *Entry) ClearDomainRules() {
	e.domainRules = nil
	e.includes = nil
}

func (e *Entry) ClearIncludes() {
	e.includes = nil
}

func (e *Entry) GetIncludes() []IncludeRef {
	if len(e.includes) == 0 {
		return nil
	}
	out := make([]IncludeRef, 0, len(e.includes))
	for ref := range e.includes {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b IncludeRef) int {
		if a.Target != b.Target {
			return strings.Compare(a.Target, b.Target)
		}
		if a.Attr != b.Attr {
			return strings.Compare(a.Attr, b.Attr)
		}
		if a.Negate != b.Negate {
			if a.Negate {
				return 1
			}
			return -1
		}
		return 0
	})
	return out
}

func (e *Entry) GetDomainRules() []DomainRule {
	if len(e.domainRules) == 0 {
		return nil
	}
	out := make([]DomainRule, 0, len(e.domainRules))
	for _, r := range e.domainRules {
		copied := DomainRule{
			Type:  r.Type,
			Value: r.Value,
		}
		if len(r.Attrs) > 0 {
			copied.Attrs = append([]string(nil), r.Attrs...)
		}
		out = append(out, copied)
	}
	slices.SortFunc(out, func(a, b DomainRule) int {
		if a.Type != b.Type {
			return strings.Compare(string(a.Type), string(b.Type))
		}
		return strings.Compare(a.Value, b.Value)
	})
	return out
}

func (e *Entry) GetDomainRulesByType() (domains, suffixes, keywords, regexes []string) {
	for _, r := range e.domainRules {
		switch r.Type {
		case RuleTypeDomain:
			domains = append(domains, r.Value)
		case RuleTypeDomainSuffix:
			suffixes = append(suffixes, r.Value)
		case RuleTypeDomainKeyword:
			keywords = append(keywords, r.Value)
		case RuleTypeDomainRegex:
			regexes = append(regexes, r.Value)
		}
	}
	slices.Sort(domains)
	slices.Sort(suffixes)
	slices.Sort(keywords)
	slices.Sort(regexes)
	return
}

func (r DomainRule) HasAttr(attr string) bool {
	attr = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(attr, "@")))
	for _, a := range r.Attrs {
		if a == attr {
			return true
		}
	}
	return false
}

func (e *Entry) AddAdGuardRule(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if e.adguardRules == nil {
		e.adguardRules = make(map[string]struct{})
	}
	e.adguardRules[line] = struct{}{}
}

func (e *Entry) RemoveAdGuardRule(line string) {
	if len(e.adguardRules) == 0 {
		return
	}
	delete(e.adguardRules, strings.TrimSpace(line))
}

func (e *Entry) HasAdGuardRules() bool {
	return len(e.adguardRules) > 0
}

func (e *Entry) ClearAdGuardRules() {
	e.adguardRules = nil
}

func (e *Entry) GetAdGuardRules() []string {
	if len(e.adguardRules) == 0 {
		return nil
	}
	out := make([]string, 0, len(e.adguardRules))
	for line := range e.adguardRules {
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

func (e *Entry) hasIPv4Builder() bool {
	return e.ipv4Builder != nil
}

func (e *Entry) hasIPv6Builder() bool {
	return e.ipv6Builder != nil
}

func (e *Entry) HasIPRules() bool {
	return e.ipv4Builder != nil || e.ipv6Builder != nil
}

func (e *Entry) ClearIPRules() {
	e.ipv4Builder = nil
	e.ipv4Set = nil
	e.ipv6Builder = nil
	e.ipv6Set = nil
}

func (e *Entry) AddPrefix(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil
	}
	var prefix netip.Prefix
	var err error
	if strings.Contains(cidr, "/") {
		prefix, err = netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		addr := prefix.Addr()
		if addr.Is4In6() {
			if prefix.Bits() < 96 {
				return ErrInvalidCIDR
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, prefix.Bits()-96)
		}
	} else {
		addr, err := netip.ParseAddr(cidr)
		if err != nil {
			return err
		}
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		if e.ipv4Builder == nil {
			e.ipv4Builder = new(netipx.IPSetBuilder)
		}
		e.ipv4Builder.AddPrefix(prefix)
		e.ipv4Set = nil
		return nil
	}
	if prefix.Addr().Is6() {
		if e.ipv6Builder == nil {
			e.ipv6Builder = new(netipx.IPSetBuilder)
		}
		e.ipv6Builder.AddPrefix(prefix)
		e.ipv6Set = nil
		return nil
	}
	return ErrInvalidCIDR
}

func (e *Entry) GetIPv4Set() (*netipx.IPSet, error) {
	if e.ipv4Builder == nil {
		return nil, nil
	}
	if e.ipv4Set != nil {
		return e.ipv4Set, nil
	}
	set, err := e.ipv4Builder.IPSet()
	if err != nil {
		return nil, err
	}
	e.ipv4Set = set
	return set, nil
}

func (e *Entry) GetIPv6Set() (*netipx.IPSet, error) {
	if e.ipv6Builder == nil {
		return nil, nil
	}
	if e.ipv6Set != nil {
		return e.ipv6Set, nil
	}
	set, err := e.ipv6Builder.IPSet()
	if err != nil {
		return nil, err
	}
	e.ipv6Set = set
	return set, nil
}

func (e *Entry) MarshalIPText(opts ...IgnoreIPOption) ([]string, error) {
	var ignoreIPType IPType
	for _, opt := range opts {
		if opt != nil {
			ignoreIPType = opt()
		}
	}

	var result []string
	if ignoreIPType != IPv4 && e.ipv4Builder != nil {
		set, err := e.GetIPv4Set()
		if err != nil {
			return nil, err
		}
		for _, p := range set.Prefixes() {
			result = append(result, p.String())
		}
	}
	if ignoreIPType != IPv6 && e.ipv6Builder != nil {
		set, err := e.GetIPv6Set()
		if err != nil {
			return nil, err
		}
		for _, p := range set.Prefixes() {
			result = append(result, p.String())
		}
	}
	return result, nil
}

func (e *Entry) MarshalIPRange(opts ...IgnoreIPOption) ([]netipx.IPRange, error) {
	var ignoreIPType IPType
	for _, opt := range opts {
		if opt != nil {
			ignoreIPType = opt()
		}
	}

	var result []netipx.IPRange
	if ignoreIPType != IPv4 && e.ipv4Builder != nil {
		set, err := e.GetIPv4Set()
		if err != nil {
			return nil, err
		}
		result = append(result, set.Ranges()...)
	}
	if ignoreIPType != IPv6 && e.ipv6Builder != nil {
		set, err := e.GetIPv6Set()
		if err != nil {
			return nil, err
		}
		result = append(result, set.Ranges()...)
	}
	return result, nil
}
