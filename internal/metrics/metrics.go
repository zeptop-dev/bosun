// Package metrics serves a Prometheus text-format endpoint without pulling
// in a client library. Values are gathered on each scrape from the
// registered sources.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Sample is one metric line.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Source produces samples on demand.
type Source func() []Sample

// Registry collects sources and renders them.
type Registry struct {
	mu      sync.RWMutex
	sources []Source
	help    map[string]string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{help: map[string]string{}} }

// Describe sets HELP/TYPE text for a metric name. Type is gauge or counter.
func (r *Registry) Describe(name, typ, help string) {
	r.mu.Lock()
	r.help[name] = typ + "|" + help
	r.mu.Unlock()
}

// Add registers a source.
func (r *Registry) Add(s Source) {
	r.mu.Lock()
	r.sources = append(r.sources, s)
	r.mu.Unlock()
}

// Render writes the exposition text.
func (r *Registry) Render() string {
	r.mu.RLock()
	sources := append([]Source(nil), r.sources...)
	help := r.help
	r.mu.RUnlock()

	byName := map[string][]Sample{}
	for _, s := range sources {
		for _, smp := range s() {
			byName[smp.Name] = append(byName[smp.Name], smp)
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		if h, ok := help[n]; ok {
			typ, text, _ := strings.Cut(h, "|")
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", n, text, n, typ)
		}
		for _, smp := range byName[n] {
			b.WriteString(n)
			if len(smp.Labels) > 0 {
				keys := make([]string, 0, len(smp.Labels))
				for k := range smp.Labels {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				b.WriteByte('{')
				for i, k := range keys {
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, `%s=%q`, k, smp.Labels[k])
				}
				b.WriteByte('}')
			}
			fmt.Fprintf(&b, " %g\n", smp.Value)
		}
	}
	return b.String()
}

// Handler serves /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})
}
