package subdesign

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/subscription"
	"gopkg.in/yaml.v3"
)

// Uses a real, separately installed client. Only geographic database files are
// read from the supplied directory, never the user's client configuration.
// Remote rule providers are replaced by local synthetic files to keep this a
// deterministic, network-free parser check rather than a network availability test.
func TestMihomoDesignerConfigurationsLive(t *testing.T) {
	binary, geoDir := os.Getenv("BOSUN_MIHOMO_TEST_BINARY"), os.Getenv("BOSUN_MIHOMO_GEODATA_DIR")
	if binary == "" || geoDir == "" {
		t.Skip("set BOSUN_MIHOMO_TEST_BINARY and BOSUN_MIHOMO_GEODATA_DIR")
	}
	designs := map[string]Design{}
	basic, _ := Preset("basic")
	designs["basic"] = basic
	pinned := clone(basic)
	pinned.Enhancements.ClaudeRules = syntheticClaudeRules()
	designs["pinned-claude-rules"] = pinned
	files, _ := filepath.Glob(filepath.Join(os.Getenv("BOSUN_ACL4SSR_PRESET_DIR"), "*.ini"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseACL4SSR(filepath.Base(f), string(b))
		if err != nil {
			t.Fatal(err)
		}
		designs[filepath.Base(f)] = d
	}
	for name, d := range designs {
		t.Run(name, func(t *testing.T) {
			for _, empty := range []bool{false, true} {
				mode := "nodes"
				if empty {
					mode = "empty"
				}
				t.Run(mode, func(t *testing.T) {
					d.Enhancements = Enhancements{Regions: true, NodeDualStack: true, DNSProtection: true, Claude: true, WebRTC: true, QUIC: true, ClaudeRules: d.Enhancements.ClaudeRules}
					tpl, err := d.Render("clash")
					if err != nil {
						t.Fatal(err)
					}
					lines := testLines()
					if empty {
						lines = nil
					}
					out, err := subscription.Clash{}.RenderWith(lines, subscription.Account{}, tpl)
					if err != nil {
						t.Fatal(err)
					}
					var doc map[string]any
					if err = yaml.Unmarshal(out, &doc); err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					for _, name := range []string{"Country.mmdb", "geoip.dat", "geosite.dat"} {
						b, err := os.ReadFile(filepath.Join(geoDir, name))
						if err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if providers, ok := doc["rule-providers"].(map[string]any); ok {
						for key, value := range providers {
							p := value.(map[string]any)
							p["type"] = "file"
							delete(p, "url")
							delete(p, "interval")
							p["path"] = "./" + key + ".list"
							if err = os.WriteFile(filepath.Join(dir, key+".list"), []byte("DOMAIN,example.com\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					rendered, err := yaml.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(dir, "config.yaml")
					if err = os.WriteFile(file, rendered, 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, "-t", "-d", dir, "-f", file)
					if b, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("mihomo rejected configuration: %v\n%s", err, b)
					}
				})
			}
		})
	}
}
