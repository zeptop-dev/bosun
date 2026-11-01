package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
)

func TestCaptainDownloadSourceValidationAndCompatibility(t *testing.T) {
	for _, tc := range []struct {
		source, endpoint, driver string
		wantErr                  bool
	}{
		{"", "https://example.com", "captain", false},
		{"github", "https://example.com", "captain", false},
		{"captain", "https://example.com:18443", "captain", false},
		{"captain", "https://[2001:db8::1]:18443", "captain", false},
		{"typo", "https://example.com", "captain", true},
		{"captain", "https://example.com", "local", true},
		{"captain", "http://example.com", "captain", true},
		{"captain", "https://user:password@example.com", "captain", true},
	} {
		t.Run(tc.source+tc.endpoint+tc.driver, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "config.yaml")
			raw := fmt.Sprintf("data_dir: %s\ncores:\n  xray: {}\npanel:\n  driver: %s\n  captain:\n    url: %q\n    download_source: %q\n    pair_code: ABCD\n", dir, tc.driver, tc.endpoint, tc.source)
			os.WriteFile(p, []byte(raw), 0600)
			cfg, err := Load(p)
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			downloads, err := cfg.Downloads()
			if err != nil {
				t.Fatal(err)
			}
			if tc.source == "captain" {
				if downloads == nil || downloads.BaseURL != tc.endpoint || downloads.TokenFile != filepath.Join(dir, "captain.token") || cfg.MinVersion != agentdownload.MinVersion {
					t.Fatalf("bad delivery configuration %+v", cfg.Panel.Captain)
				}
			} else if downloads != nil {
				t.Fatal("legacy source changed")
			}
		})
	}
}
