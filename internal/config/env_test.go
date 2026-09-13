package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvSelectsCaptain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("cores:\n  singbox: {}\npanel:\n  driver: local\nweb:\n  listen: \":2053\"\n"), 0o600)
	t.Setenv("BOSUN_CAPTAIN", "https://panel.test")
	t.Setenv("BOSUN_PAIR", "ABCD-EFGH")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Panel.Driver != "captain" || c.Panel.Captain.URL != "https://panel.test" || c.Panel.Captain.PairCode != "ABCD-EFGH" || c.Web != nil {
		t.Fatalf("env override not applied: %+v web=%v", c.Panel, c.Web)
	}
	if c.Panel.Captain.TokenFile == "" {
		t.Fatal("token file default missing")
	}
}
