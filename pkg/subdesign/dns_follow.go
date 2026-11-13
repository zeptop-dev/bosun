package subdesign

import "fmt"

// MainDNSPolicy uses structure rather than translated preset names.
func (d *Design) MainDNSPolicy() (string, error) {
	if d.Enhancements.DNSPolicy != "" {
		return d.Enhancements.DNSPolicy, nil
	}
	for _, g := range d.Groups {
		if g.Type == "select" {
			for _, m := range g.Members {
				if m == "@all" {
					return g.Name, nil
				}
			}
		}
	}
	for _, g := range d.Groups {
		if g.Name == d.Final {
			return g.Name, nil
		}
	}
	return "", fmt.Errorf("choose a main proxy group for DNS")
}
func (d *Design) validateFollowDNS() error {
	policy, err := d.MainDNSPolicy()
	if err != nil {
		return err
	}
	groups := map[string]Group{}
	for _, g := range d.Groups {
		groups[g.Name] = g
	}
	if _, ok := groups[policy]; !ok {
		return fmt.Errorf("DNS main policy %q is not a proxy group", policy)
	}
	// DIRECT is an explicit manual choice, never an automatic failover candidate.
	var hasDirect func(string, map[string]bool) bool
	hasDirect = func(name string, seen map[string]bool) bool {
		if name == "DIRECT" {
			return true
		}
		if seen[name] {
			return false
		}
		seen[name] = true
		for _, m := range groups[name].Members {
			if hasDirect(m, seen) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	var walk func(string) error
	walk = func(name string) error {
		if seen[name] {
			return nil
		}
		seen[name] = true
		g, ok := groups[name]
		if !ok {
			return nil
		}
		if g.Type != "select" && hasDirect(name, map[string]bool{}) {
			return fmt.Errorf("DNS following cannot use automatic DIRECT candidates in %q", name)
		}
		for _, m := range g.Members {
			if err := walk(m); err != nil {
				return err
			}
		}
		return nil
	}
	if policy == "RULES" {
		return fmt.Errorf("RULES is reserved by mihomo DNS")
	}
	for _, c := range policy {
		if c == '&' || c == '%' {
			return fmt.Errorf("DNS policy names cannot contain & or %%")
		}
	}
	return walk(policy)
}
