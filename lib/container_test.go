package lib

import "testing"

func TestContainerDomainAdGuardIP(t *testing.T) {
	c := NewContainer()

	e := NewEntry("cn")
	e.AddDomainRule(DomainRule{Type: RuleTypeDomainSuffix, Value: "Example.COM"})
	e.AddDomainRule(DomainRule{Type: RuleTypeDomainSuffix, Value: "example.com"})
	e.AddDomainRule(DomainRule{Type: RuleTypeDomain, Value: "exact.test"})
	e.AddAdGuardRule("||ads.example.com^")
	if err := e.AddPrefix("1.1.1.0/25"); err != nil {
		t.Fatal(err)
	}
	if err := e.AddPrefix("1.1.1.128/25"); err != nil {
		t.Fatal(err)
	}

	if err := c.Add(e); err != nil {
		t.Fatal(err)
	}

	got, ok := c.GetEntry("CN")
	if !ok {
		t.Fatal("CN entry not found")
	}
	domains, suffixes, _, _ := got.GetDomainRulesByType()
	if len(domains) != 1 || domains[0] != "exact.test" {
		t.Fatalf("unexpected domains: %v", domains)
	}
	if len(suffixes) != 1 || suffixes[0] != "example.com" {
		t.Fatalf("unexpected suffixes: %v", suffixes)
	}

	cidrs, err := got.MarshalIPText()
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 1 || cidrs[0] != "1.1.1.0/24" {
		t.Fatalf("expected merged CIDR 1.1.1.0/24, got %v", cidrs)
	}

	matchedDomains, found := c.LookupDomain("sub.example.com")
	if !found || len(matchedDomains) != 1 || matchedDomains[0] != "CN" {
		t.Fatalf("LookupDomain unexpected: %v %v", matchedDomains, found)
	}

	matchedIPs, found, err := c.LookupIP("1.1.1.42")
	if err != nil || !found || len(matchedIPs) != 1 || matchedIPs[0] != "CN" {
		t.Fatalf("LookupIP unexpected: %v %v %v", matchedIPs, found, err)
	}
}
