package metrics

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	r := NewRegistry()
	r.Describe("bosun_up", "gauge", "1 if running")
	r.Add(func() []Sample {
		return []Sample{
			{Name: "bosun_up", Value: 1},
			{Name: "bosun_forward_bytes_total", Labels: map[string]string{"tag": "a", "dir": "in"}, Value: 42},
		}
	})
	out := r.Render()
	for _, want := range []string{
		"# HELP bosun_up 1 if running", "# TYPE bosun_up gauge", "bosun_up 1\n",
		`bosun_forward_bytes_total{dir="in",tag="a"} 42`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
