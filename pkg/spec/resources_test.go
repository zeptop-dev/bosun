package spec

import "testing"

func TestResourceOptionsManagedNetworkDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"eth0", true},
		{"enp1s0", true},
		{"bwg1", false},
		{"bwg2", false},
		{"bwg16383", false},
		{"ifb-bosun", false},
		{"ifb-bosun-up", false},
		{"wg0", true},
		{"tun0", true},
		{"ifb0", true},
		{"ifb-other", true},
		{"ifb-bosun-custom", true},
		{"bwg", true},
		{"bwg0", true},
		{"bwg01", true},
		{"bwg+1", true},
		{"bwg-1", true},
		{"bwg16384", true},
		{"bwg999999999999999999999999", true},
		{"bwg1-custom", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (ResourceOptions{}).Includes(tc.name); got != tc.want {
				t.Fatalf("default Includes(%q) = %v, want %v", tc.name, got, tc.want)
			}
			// An explicit choice overrides defaults, while exclusions always win.
			o := ResourceOptions{IncludeInterfaces: []string{tc.name}}
			if !o.Includes(tc.name) || o.Includes("other0") {
				t.Fatal("explicit inclusion ignored")
			}
			o.ExcludeInterfaces = []string{tc.name}
			if o.Includes(tc.name) {
				t.Fatal("explicit exclusion ignored")
			}
		})
	}
}
