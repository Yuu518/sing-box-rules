package lib

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"go4.org/netipx"
)

type Container interface {
	GetEntry(name string) (*Entry, bool)
	GetOrCreateEntry(name string) *Entry
	Len() int
	Add(entry *Entry, opts ...IgnoreIPOption) error
	Replace(entry *Entry, kind EntryKind, opts ...IgnoreIPOption) error
	Remove(entry *Entry, rCase CaseRemove, kind EntryKind, opts ...IgnoreIPOption) error
	Loop() <-chan *Entry
	SortedNames() []string
	LookupDomain(domain string, searchList ...string) ([]string, bool)
	LookupIP(ipOrCidr string, searchList ...string) ([]string, bool, error)
}

type container struct {
	entries map[string]*Entry
}

func NewContainer() Container {
	return &container{
		entries: make(map[string]*Entry),
	}
}

func (c *container) isValid() bool {
	return c.entries != nil
}

func (c *container) GetEntry(name string) (*Entry, bool) {
	if !c.isValid() {
		return nil, false
	}
	val, ok := c.entries[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return nil, false
	}
	return val, true
}

func (c *container) GetOrCreateEntry(name string) *Entry {
	key := strings.ToUpper(strings.TrimSpace(name))
	if val, ok := c.entries[key]; ok {
		return val
	}
	entry := NewEntry(key)
	c.entries[key] = entry
	return entry
}

func (c *container) Len() int {
	if !c.isValid() {
		return 0
	}
	return len(c.entries)
}

func (c *container) Loop() <-chan *Entry {
	ch := make(chan *Entry, c.Len())
	for _, val := range c.entries {
		ch <- val
	}
	close(ch)
	return ch
}

func (c *container) SortedNames() []string {
	names := make([]string, 0, len(c.entries))
	for name := range c.entries {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (c *container) Add(entry *Entry, opts ...IgnoreIPOption) error {
	var ignoreIPType IPType
	for _, opt := range opts {
		if opt != nil {
			ignoreIPType = opt()
		}
	}

	name := entry.GetName()
	val, found := c.GetEntry(name)
	if !found {
		val = NewEntry(name)
		c.entries[name] = val
	}

	for _, r := range entry.domainRules {
		val.AddDomainRule(*r)
	}
	for inc := range entry.includes {
		val.AddInclude(inc)
	}
	for line := range entry.adguardRules {
		val.AddAdGuardRule(line)
	}

	if ignoreIPType != IPv4 && entry.hasIPv4Builder() {
		ipv4set, err := entry.GetIPv4Set()
		if err != nil {
			return err
		}
		if ipv4set != nil {
			if !val.hasIPv4Builder() {
				val.ipv4Builder = new(netipx.IPSetBuilder)
			}
			val.ipv4Builder.AddSet(ipv4set)
			val.ipv4Set = nil
		}
	}

	if ignoreIPType != IPv6 && entry.hasIPv6Builder() {
		ipv6set, err := entry.GetIPv6Set()
		if err != nil {
			return err
		}
		if ipv6set != nil {
			if !val.hasIPv6Builder() {
				val.ipv6Builder = new(netipx.IPSetBuilder)
			}
			val.ipv6Builder.AddSet(ipv6set)
			val.ipv6Set = nil
		}
	}

	return nil
}

func (c *container) Replace(entry *Entry, kind EntryKind, opts ...IgnoreIPOption) error {
	name := entry.GetName()
	if val, found := c.GetEntry(name); found {
		switch kind {
		case EntryKindDomain:
			val.ClearDomainRules()
		case EntryKindAdGuard:
			val.ClearAdGuardRules()
		case EntryKindIP:
			val.ClearIPRules()
		default:
			delete(c.entries, name)
		}
	}
	return c.Add(entry, opts...)
}

func (c *container) Remove(entry *Entry, rCase CaseRemove, kind EntryKind, opts ...IgnoreIPOption) error {
	name := entry.GetName()
	val, found := c.GetEntry(name)
	if !found {
		return nil
	}

	var ignoreIPType IPType
	for _, opt := range opts {
		if opt != nil {
			ignoreIPType = opt()
		}
	}

	switch rCase {
	case CaseRemoveRule:
		if kind == EntryKindAll || kind == EntryKindDomain {
			for _, r := range entry.domainRules {
				val.RemoveDomainRule(r.Type, r.Value)
			}
		}
		if kind == EntryKindAll || kind == EntryKindAdGuard {
			for line := range entry.adguardRules {
				val.RemoveAdGuardRule(line)
			}
		}
		if kind == EntryKindAll || kind == EntryKindIP {
			if ignoreIPType != IPv4 && entry.hasIPv4Builder() && val.hasIPv4Builder() {
				ipv4set, err := entry.GetIPv4Set()
				if err != nil {
					return err
				}
				if ipv4set != nil {
					val.ipv4Builder.RemoveSet(ipv4set)
					val.ipv4Set = nil
				}
			}
			if ignoreIPType != IPv6 && entry.hasIPv6Builder() && val.hasIPv6Builder() {
				ipv6set, err := entry.GetIPv6Set()
				if err != nil {
					return err
				}
				if ipv6set != nil {
					val.ipv6Builder.RemoveSet(ipv6set)
					val.ipv6Set = nil
				}
			}
		}

	case CaseRemoveEntry:
		switch kind {
		case EntryKindDomain:
			val.ClearDomainRules()
		case EntryKindAdGuard:
			val.ClearAdGuardRules()
		case EntryKindIP:
			switch ignoreIPType {
			case IPv4:
				val.ipv6Builder = nil
				val.ipv6Set = nil
			case IPv6:
				val.ipv4Builder = nil
				val.ipv4Set = nil
			default:
				val.ClearIPRules()
			}
		default:
			delete(c.entries, name)
		}

	default:
		return fmt.Errorf("unknown remove case %d", rCase)
	}

	return nil
}

func (c *container) LookupDomain(domain string, searchList ...string) ([]string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, false
	}

	searchMap := make(map[string]bool)
	for _, name := range searchList {
		if name = strings.ToUpper(strings.TrimSpace(name)); name != "" {
			searchMap[name] = true
		}
	}

	var matched []string
	for _, entry := range c.entries {
		if len(searchMap) > 0 && !searchMap[entry.GetName()] {
			continue
		}
		if !entry.HasDomainRules() {
			continue
		}
		if matchDomainInEntry(domain, entry) {
			matched = append(matched, entry.GetName())
		}
	}
	slices.Sort(matched)
	return matched, len(matched) > 0
}

func matchDomainInEntry(domain string, entry *Entry) bool {
	if _, ok := entry.domainRules[domainRuleKey{ruleType: RuleTypeDomain, value: domain}]; ok {
		return true
	}
	parts := strings.Split(domain, ".")
	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		if _, ok := entry.domainRules[domainRuleKey{ruleType: RuleTypeDomainSuffix, value: candidate}]; ok {
			return true
		}
	}
	for _, r := range entry.domainRules {
		switch r.Type {
		case RuleTypeDomainKeyword:
			if strings.Contains(domain, r.Value) {
				return true
			}
		case RuleTypeDomainRegex:
			if re, err := regexp.Compile(r.Value); err == nil && re.MatchString(domain) {
				return true
			}
		}
	}
	return false
}

func (c *container) LookupIP(ipOrCidr string, searchList ...string) ([]string, bool, error) {
	if strings.Contains(ipOrCidr, "/") {
		prefix, err := netip.ParsePrefix(ipOrCidr)
		if err != nil {
			return nil, false, err
		}
		addr := prefix.Addr()
		if addr.Is4In6() {
			if prefix.Bits() < 96 {
				return nil, false, ErrInvalidCIDR
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, prefix.Bits()-96)
		}
		if addr.Is4() {
			return c.lookupIP(prefix, IPv4, searchList...)
		}
		if addr.Is6() {
			return c.lookupIP(prefix, IPv6, searchList...)
		}
		return nil, false, nil
	}

	addr, err := netip.ParseAddr(ipOrCidr)
	if err != nil {
		return nil, false, err
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return c.lookupIP(addr, IPv4, searchList...)
	}
	if addr.Is6() {
		return c.lookupIP(addr, IPv6, searchList...)
	}
	return nil, false, nil
}

func (c *container) lookupIP(addrOrPrefix any, iptype IPType, searchList ...string) ([]string, bool, error) {
	searchMap := make(map[string]bool)
	for _, name := range searchList {
		if name = strings.ToUpper(strings.TrimSpace(name)); name != "" {
			searchMap[name] = true
		}
	}

	var result []string
	for _, entry := range c.entries {
		if len(searchMap) > 0 && !searchMap[entry.GetName()] {
			continue
		}

		var ipset *netipx.IPSet
		var err error
		switch iptype {
		case IPv4:
			if !entry.hasIPv4Builder() {
				continue
			}
			ipset, err = entry.GetIPv4Set()
		case IPv6:
			if !entry.hasIPv6Builder() {
				continue
			}
			ipset, err = entry.GetIPv6Set()
		}
		if err != nil {
			return nil, false, err
		}
		if ipset == nil {
			continue
		}

		switch v := addrOrPrefix.(type) {
		case netip.Prefix:
			if ipset.ContainsPrefix(v) {
				result = append(result, entry.GetName())
			}
		case netip.Addr:
			if ipset.Contains(v) {
				result = append(result, entry.GetName())
			}
		}
	}

	slices.Sort(result)
	return result, len(result) > 0, nil
}
