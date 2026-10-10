package hostupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// A backup must cover all mutable application state. Custom data locations
// are rejected explicitly instead of producing an incomplete recovery copy.
func standardLayout(product string, raw []byte) error {
	var c struct {
		Data     string `yaml:"data_dir"`
		Database struct {
			DSN string `yaml:"dsn"`
		} `yaml:"database"`
		Web struct {
			State string `yaml:"state_file"`
		} `yaml:"web"`
		Panel struct {
			Captain struct {
				Token string `yaml:"token_file"`
			} `yaml:"captain"`
		} `yaml:"panel"`
	}
	if yaml.Unmarshal(raw, &c) != nil {
		return errors.New("cannot validate application data paths")
	}
	base := "/var/lib/" + product
	if c.Data != "" && filepath.Clean(c.Data) != base {
		return errors.New("custom data_dir requires an operator-managed backup/upgrade/uninstall")
	}
	for _, path := range []string{c.Web.State, c.Panel.Captain.Token} {
		if path != "" && !inside(filepath.Clean(path), base) {
			return errors.New("application state is outside the standard data directory")
		}
	}
	if product == "captain" && c.Database.DSN != "" && (!strings.HasPrefix(c.Database.DSN, base+"/") || !inside(filepath.Clean(c.Database.DSN), base)) {
		return errors.New("database is outside the standard data directory")
	}
	return nil
}

func containerLayout(ctx context.Context, run runner, product, id string) error {
	dir, err := os.MkdirTemp("", "app-layout-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.yaml")
	if _, err = run(ctx, "docker", "cp", id+":/etc/"+product+"/config.yaml", path); err != nil {
		return errors.New("cannot read installed application configuration")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return standardLayout(product, b)
}

// CheckLayoutFile validates an installer's backup/removal scope without loading
// the application or applying any database migrations.
func CheckLayoutFile(product, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return standardLayout(product, b)
}
