package hostupdate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Uninstall is a host-only CLI, deliberately absent from the updater socket.
// It deletes only this product's resources, never prunes a shared Docker host.
func Uninstall(product string, args []string, network func(context.Context, string) error) error {
	f := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	dir := f.String("dir", "/opt/"+product, "installation directory")
	keep := f.Bool("keep-data", false, "keep configuration and data")
	yes := f.Bool("yes", false, "confirm permanent removal")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !validProduct(product) || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("uninstall requires root on the Linux host")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return errors.New("run uninstall on the host")
	}
	if !*yes {
		return errors.New("uninstall permanently deletes configuration, database, backups and certificates; pass --yes to confirm")
	}
	if !pathRE.MatchString(*dir) || filepath.Clean(*dir) != *dir || *dir != "/opt/"+product {
		return errors.New("automatic full removal requires the standard /opt/" + product + " installation directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if b, err := os.ReadFile("/etc/" + product + "/config.yaml"); err == nil && !*keep {
		if err = standardLayout(product, b); err != nil {
			return err
		}
	}
	return uninstall(ctx, product, *dir, *keep, command, network)
}

func stopService(ctx context.Context, run runner, name string) error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		// Missing units are harmless. A failed stop of an installed unit is not.
		if _, err = os.Stat("/etc/systemd/system/" + name + ".service"); err == nil {
			if _, err = run(ctx, "systemctl", "disable", "--now", name); err != nil {
				return err
			}
		}
	}
	if _, err := os.Stat("/etc/init.d/" + name); err == nil {
		if _, err = run(ctx, "rc-service", name, "stop"); err != nil {
			return err
		}
		if _, err = run(ctx, "rc-update", "del", name, "default"); err != nil {
			return err
		}
	}
	return nil
}

func uninstall(ctx context.Context, p, dir string, keep bool, run runner, network func(context.Context, string) error) error {
	if status := Check(ctx, p); status.Job != nil && status.Job.Active() {
		return errors.New("upgrade is in progress; wait for it before uninstalling")
	}
	if err := stopService(ctx, run, p+"-updater"); err != nil {
		return err
	}
	if err := stopService(ctx, run, p); err != nil {
		return err
	}
	inventoryPath := filepath.Join(stateDir(p), "uninstall.json")
	inv := removalInventory{Volumes: map[string]bool{}, Projects: map[string]bool{}, Binds: map[string]bool{}, Images: map[string]bool{}}
	if b, err := os.ReadFile(inventoryPath); err == nil {
		if trusted(inventoryPath) != nil || json.Unmarshal(b, &inv) != nil {
			return errors.New("invalid uninstall inventory")
		}
	}
	volumes, projects, binds := inv.Volumes, inv.Projects, inv.Binds
	images := inv.Images
	if images == nil {
		images = map[string]bool{}
	}
	if volumes == nil {
		volumes = map[string]bool{}
	}
	if projects == nil {
		projects = map[string]bool{}
	}
	if binds == nil {
		binds = map[string]bool{}
	}
	if _, err := exec.LookPath("docker"); err == nil {
		// Discover old Compose installs too, including those without an updater.
		b, err := run(ctx, "docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
		if err != nil {
			return errors.New("Docker is unavailable; refusing to report a complete uninstall")
		}
		var selected []container
		for _, id := range strings.Fields(string(b)) {
			b, err = run(ctx, "docker", "inspect", id)
			if err != nil {
				return err
			}
			var all []container
			if json.Unmarshal(b, &all) != nil || len(all) != 1 {
				return errors.New("invalid Docker metadata")
			}
			c := all[0]
			service := c.Config.Labels["com.docker.compose.service"]
			if service != "" {
				if service != p {
					continue
				}
				if c.Config.Labels["com.docker.compose.project.working_dir"] != dir {
					return errors.New("another Compose installation exists outside the standard directory; remove it explicitly")
				}
			} else {
				image := c.Config.Image
				if !(strings.HasPrefix(image, "zeptop/"+p+":") || strings.HasPrefix(image, "ghcr.io/zeptop-dev/"+p+":") || strings.HasPrefix(image, "zeptop/"+p+"@") || strings.HasPrefix(image, "ghcr.io/zeptop-dev/"+p+"@")) {
					continue
				}
			}
			if !keep {
				if err = containerLayout(ctx, run, p, c.ID); err != nil {
					return err
				}
			}
			if project := c.Config.Labels["com.docker.compose.project"]; project != "" {
				projects[project] = true
			}
			for _, m := range c.Mounts {
				if m.Destination != "/var/lib/"+p && m.Destination != "/etc/"+p && m.Destination != "/etc/"+p+"/config.yaml" {
					continue
				}
				if m.Type == "volume" {
					volumes[m.Name] = true
				}
				if m.Type == "bind" {
					if !(inside(m.Source, dir) || inside(m.Source, "/etc/"+p) || inside(m.Source, "/var/lib/"+p)) {
						return errors.New("external application data mount found; move or remove it explicitly before a full uninstall")
					}
					binds[m.Source] = true
				}
			}
			if imageIDRE.MatchString(c.Image) {
				images[c.Image] = true
			}
			selected = append(selected, c)
		}
		if err = ownedDir(stateDir(p), 0700); err != nil {
			return err
		}
		if err = saveJSON(inventoryPath, removalInventory{volumes, projects, binds, images}); err != nil {
			return err
		}
		if !keep { // Check sharing before deleting any container or volume.
			ids := map[string]bool{}
			for _, c := range selected {
				ids[c.ID] = true
			}
			for v := range volumes {
				b, e := run(ctx, "docker", "ps", "--all", "--no-trunc", "--filter", "volume="+v, "--quiet")
				if e != nil {
					return e
				}
				for _, id := range strings.Fields(string(b)) {
					if !ids[id] {
						return errors.New("application volume is shared with another container; uninstall stopped")
					}
				}
			}
		}
		// The installer runs this worker outside Docker.
		for _, c := range selected {
			if _, err = run(ctx, "docker", "stop", "--time", "60", c.ID); err != nil {
				return err
			}
		}
		if network != nil {
			// Recover firewall ownership state from the stopped container before
			// cleanup, even when data lives in an opaque Docker volume.
			for _, c := range selected {
				tmp, e := os.MkdirTemp("", "bosun-uninstall-*")
				if e != nil {
					return e
				}
				_, e = run(ctx, "docker", "cp", c.ID+":/var/lib/bosun", filepath.Join(tmp, "data"))
				if e != nil {
					_ = os.RemoveAll(tmp)
					return errors.New("cannot recover bosun firewall ownership state")
				}
				e = network(ctx, filepath.Join(tmp, "data"))
				_ = os.RemoveAll(tmp)
				if e != nil {
					return e
				}
			}
		}
		for _, c := range selected {
			if _, err = run(ctx, "docker", "rm", c.ID); err != nil {
				return err
			}
		}
		if !keep {
			for v := range volumes {
				b, err = run(ctx, "docker", "ps", "--all", "--filter", "volume="+v, "--quiet")
				if err != nil {
					return err
				}
				if len(strings.Fields(string(b))) > 0 {
					return errors.New("application volume is still used by another container; data retained")
				}
				existing, e := run(ctx, "docker", "volume", "ls", "--format", "{{.Name}}")
				if e != nil {
					return e
				}
				exists := false
				for _, name := range strings.Fields(string(existing)) {
					if name == v {
						exists = true
					}
				}
				if !exists {
					continue
				}
				if _, err = run(ctx, "docker", "volume", "rm", v); err != nil {
					return err
				}
			}
		}
		for project := range projects {
			b, err = run(ctx, "docker", "network", "ls", "--filter", "label=com.docker.compose.project="+project, "--quiet")
			if err != nil {
				return err
			}
			for _, id := range strings.Fields(string(b)) {
				b, err = run(ctx, "docker", "network", "inspect", "--format", "{{len .Containers}}", id)
				if err != nil {
					return err
				}
				if strings.TrimSpace(string(b)) == "0" {
					if _, err = run(ctx, "docker", "network", "rm", id); err != nil {
						return err
					}
				}
			}
		}
		for image := range images {
			_, _ = run(ctx, "docker", "image", "rm", image)
		}
		// No force: Docker refuses to remove images used by other containers.
		b, err = run(ctx, "docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}")
		if err != nil {
			return err
		}
		for _, image := range strings.Fields(string(b)) {
			if strings.HasPrefix(image, "zeptop/"+p+":") || strings.HasPrefix(image, "ghcr.io/zeptop-dev/"+p+":") {
				if !strings.HasSuffix(image, ":<none>") {
					_, _ = run(ctx, "docker", "image", "rm", image)
				}
			}
		}
	} else {
		if len(volumes) > 0 || len(projects) > 0 || len(images) > 0 {
			return errors.New("Docker is missing; previously discovered container resources cannot be removed")
		}
		for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return errors.New("Docker is missing; container data cannot be verified or removed")
			}
		}
	}
	if network != nil {
		if err := network(ctx, "/var/lib/"+p); err != nil {
			return err
		}
	}
	paths := []string{
		"/etc/systemd/system/" + p + ".service", "/etc/systemd/system/" + p + ".service.d",
		"/etc/systemd/system/" + p + "-updater.service", "/etc/systemd/system/" + p + "-updater.service.d",
		"/etc/init.d/" + p, "/etc/init.d/" + p + "-updater", "/etc/conf.d/" + p,
		"/usr/local/lib/" + p + "-updater", configDir(p), "/run/" + p + "-updater",
		"/usr/local/bin/" + p, "/usr/local/bin/" + p + ".backup", "/usr/local/bin/" + p + ".backup.version", "/usr/local/bin/" + p + ".new",
		filepath.Join(dir, p), filepath.Join(dir, p+".backup"), filepath.Join(dir, p+".backup.version"), filepath.Join(dir, p+".new"),
	}
	if !keep {
		paths = append(paths, dir, "/etc/"+p, "/var/lib/"+p, stateDir(p))
		for b := range binds {
			paths = append(paths, b)
		}
	}
	logs, _ := filepath.Glob("/var/log/" + p + ".log*")
	paths = append(paths, logs...)
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if _, err = run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		_, _ = run(ctx, "systemctl", "reset-failed", p, p+"-updater")
	}
	if !keep {
		account := p
		expectedHome := "/var/lib/" + p
		if p == "bosun" {
			account = "bosun-proxy"
			expectedHome = "/nonexistent"
		}
		entry, lookupErr := user.Lookup(account)
		if lookupErr == nil && entry.HomeDir == expectedHome && entry.Uid != "0" {
			if _, e := exec.LookPath("userdel"); e == nil {
				if _, err := run(ctx, "userdel", account); err != nil {
					return err
				}
			} else if _, e = exec.LookPath("deluser"); e == nil {
				if _, err := run(ctx, "deluser", account); err != nil {
					return err
				}
			}
			if _, err := exec.LookPath("groupdel"); err == nil {
				_, _ = run(ctx, "groupdel", account)
			} else if _, err := exec.LookPath("delgroup"); err == nil {
				_, _ = run(ctx, "delgroup", account)
			}
		}
	}
	fmt.Println(p + " removed; unrelated containers, external networks and shared system packages were preserved.")
	return nil
}

type removalInventory struct {
	Volumes  map[string]bool `json:"volumes"`
	Projects map[string]bool `json:"projects"`
	Binds    map[string]bool `json:"binds"`
	Images   map[string]bool `json:"images,omitempty"`
}
