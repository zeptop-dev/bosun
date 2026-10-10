package hostupdate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var pathRE = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
var imageIDRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Trust all path components, not just the file: a writable parent allows an
// unprivileged application to replace an otherwise root-owned compose file.
func trusted(path string) error {
	for {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("updater requires root-owned, non-writable deployment path: %s", path)
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func ownedDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := trusted(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func validateConfig(c Config) error {
	if !validProduct(c.Product) || !nameRE.MatchString(c.Project) || !pathRE.MatchString(c.Dir) || filepath.Clean(c.Dir) != c.Dir || c.Dir == "/" || len(c.Files) == 0 {
		return errors.New("invalid updater registration")
	}
	if c.Repository != "zeptop/"+c.Product && c.Repository != "ghcr.io/zeptop-dev/"+c.Product {
		return errors.New("only official images are supported")
	}
	if c.UID != 0 && !(c.Product == "captain" && c.UID == 1000) {
		return errors.New("unsupported container user")
	}
	if err := trusted(c.Dir); err != nil {
		return err
	}
	for _, p := range append(append([]string{}, c.Files...), filepath.Join(c.Dir, ".env")) {
		if !pathRE.MatchString(p) || filepath.Clean(p) != p {
			return errors.New("invalid compose path")
		}
		if _, err := os.Lstat(p); os.IsNotExist(err) && filepath.Base(p) == ".env" {
			continue
		}
		if err := trusted(p); err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// Includes/extends introduce additional executable deployment inputs.
		// Register a self-contained compose deployment instead.
		if filepath.Base(p) != ".env" && (regexp.MustCompile(`(?m)^\s*(include|extends)\s*:`).Match(b)) {
			return errors.New("compose include/extends is not supported by the host updater")
		}
	}
	return nil
}

type container struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Config struct {
		Image, User string
		Cmd         []string
		Entrypoint  []string
		Labels      map[string]string
	} `json:"Config"`
	Mounts []struct {
		Type, Name, Source, Destination string
		RW                              bool
	} `json:"Mounts"`
}

func discover(ctx context.Context, run runner, product, dir string) (Config, error) {
	c := Config{Product: product, Dir: dir}
	b, err := run(ctx, "docker", "ps", "--all", "--filter", "label=com.docker.compose.service="+product, "--format", "{{.ID}}")
	if err != nil {
		return c, err
	}
	found := 0
	for _, id := range strings.Fields(string(b)) {
		b, err = run(ctx, "docker", "inspect", id)
		if err != nil {
			return c, err
		}
		var v []container
		if json.Unmarshal(b, &v) != nil || len(v) != 1 {
			return c, errors.New("invalid container metadata")
		}
		d := v[0]
		if d.Config.Labels["com.docker.compose.project.working_dir"] != dir {
			continue
		}
		found++
		mode := "run"
		if product == "captain" {
			mode = "serve"
		}
		args := strings.Join(d.Config.Cmd, " ")
		if args != mode && args != mode+" -c /etc/"+product+"/config.yaml" {
			return c, errors.New("custom application command requires manual host upgrades")
		}
		if err = containerLayout(ctx, run, product, d.ID); err != nil {
			return c, err
		}
		c.Project = d.Config.Labels["com.docker.compose.project"]
		for _, p := range strings.Split(d.Config.Labels["com.docker.compose.project.config_files"], ",") {
			if p != overridePath(c) {
				c.Files = append(c.Files, p)
			}
		}
		image := d.Config.Image
		for _, repo := range []string{"zeptop/" + product, "ghcr.io/zeptop-dev/" + product} {
			if strings.HasPrefix(image, repo+":") || strings.HasPrefix(image, repo+"@") {
				c.Repository = repo
			}
		}
		if imageIDRE.MatchString(image) { // Already registered, pinned by updater.
			var old Config
			b, e := os.ReadFile(filepath.Join(configDir(product), "config.json"))
			if e == nil && json.Unmarshal(b, &old) == nil && old.Dir == dir {
				c.Repository = old.Repository
			}
		}
		switch d.Config.User {
		case "", "0", "0:0", "root":
			c.UID = 0
		case "captain", "1000", "1000:1000":
			if product != "captain" {
				return c, errors.New("unsupported user")
			}
			c.UID = 1000
		default:
			return c, errors.New("unsupported user mapping; use a manual host upgrade")
		}
		data := false
		for _, m := range d.Mounts {
			if m.Destination == "/var/lib/"+product {
				data = true
			}
			// A writable deployment mount defeats the narrow socket boundary.
			if m.Type == "bind" && m.RW && (inside(dir, m.Source) || inside(configDir(product), m.Source) || inside(stateDir(product), m.Source)) {
				return c, errors.New("application can write updater deployment inputs")
			}
		}
		if !data {
			return c, errors.New("application data must be mounted at /var/lib/" + product)
		}
	}
	if found != 1 {
		return c, errors.New("expected exactly one Compose deployment in the selected directory")
	}
	return c, validateConfig(c)
}

func inside(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, strings.TrimRight(parent, "/")+"/")
}

// Setup is host-only. No request accepted over the socket can register a
// deployment, select a path, change repositories, or uninstall anything.
func setup(product, dir string) error {
	if status := Check(context.Background(), product); status.Job != nil && status.Job.Active() {
		return errors.New("upgrade in progress; registration cannot be replaced")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, err := discover(ctx, command, product, dir)
	if err != nil {
		return err
	}
	for _, p := range []string{configDir(product), stateDir(product), "/usr/local/lib/" + product + "-updater"} {
		if err = ownedDir(p, 0700); err != nil {
			return err
		}
	}
	if err = ownedDir(filepath.Dir(socket(product)), 0711); err != nil {
		return err
	}
	b, err := os.ReadFile(mustExecutable())
	if err != nil {
		return err
	}
	exe := "/usr/local/lib/" + product + "-updater/worker"
	if err = atomic(exe, b, 0700); err != nil {
		return err
	}
	if err = saveJSON(filepath.Join(configDir(product), "config.json"), c); err != nil {
		return err
	}
	if _, err = os.Stat(overridePath(c)); os.IsNotExist(err) {
		// Preserve the running image until the first explicit upgrade.
		b, err = command(ctx, "docker", "compose", "--project-directory", dir, "--project-name", c.Project, "ps", "--all", "--quiet", product)
		if err != nil {
			return err
		}
		ids := strings.Fields(string(b))
		if len(ids) != 1 {
			return errors.New("application container disappeared")
		}
		b, err = command(ctx, "docker", "inspect", "--format", "{{.Image}}", ids[0])
		if err != nil {
			return err
		}
		image := strings.TrimSpace(string(b))
		if !imageIDRE.MatchString(image) {
			return errors.New("invalid current image")
		}
		if err = atomic(overridePath(c), override(c, image), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err = trusted(overridePath(c)); err != nil {
		return err
	}
	// Teach ordinary `docker compose up` the same override. Preserve all
	// other .env values and the original files; never rewrite the base YAML.
	env := filepath.Join(dir, ".env")
	b, err = os.ReadFile(env)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "COMPOSE_FILE=") || strings.HasPrefix(s, "export COMPOSE_FILE=") {
			continue
		}
		lines = append(lines, line)
	}
	files := append(append([]string{}, c.Files...), overridePath(c))
	lines = append(lines, "COMPOSE_FILE="+strings.Join(files, ":"))
	if err = atomic(env, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	service := product + "-updater"
	if _, e := os.Stat("/run/systemd/system"); e == nil {
		unit := "[Unit]\nDescription=" + product + " Docker updater\nAfter=docker.service\nRequires=docker.service\n[Service]\nExecStart=" + exe + " docker-updater serve\nRestart=on-failure\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
		if err = atomic("/etc/systemd/system/"+service+".service", []byte(unit), 0644); err != nil {
			return err
		}
		if _, err = command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if _, err = command(ctx, "systemctl", "enable", service); err != nil {
			return err
		}
		if _, err = command(ctx, "systemctl", "restart", service); err != nil {
			return err
		}
	} else if _, e = os.Stat("/run/openrc"); e == nil {
		unit := "#!/sbin/openrc-run\ncommand=\"" + exe + "\"\ncommand_args=\"docker-updater serve\"\nsupervisor=supervise-daemon\nrespawn_delay=3\nrespawn_max=0\ndepend() { need docker; }\n"
		if err = atomic("/etc/init.d/"+service, []byte(unit), 0755); err != nil {
			return err
		}
		if _, err = command(ctx, "rc-update", "add", service, "default"); err != nil {
			return err
		}
		if _, err = command(ctx, "rc-service", service, "restart"); err != nil {
			return err
		}
	} else {
		return errors.New("host updater requires systemd or OpenRC")
	}
	_, err = compose(ctx, command, c, "up", "--detach", "--no-deps", "--pull", "never", product)
	return err
}

func mustExecutable() string { p, _ := os.Executable(); return p }

func CLI(product string, args []string) error {
	if !validProduct(product) || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("Docker updater commands must run as root on the Linux host")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return errors.New("run Docker updater on the host, outside the application container")
	}
	if len(args) == 0 {
		return errors.New("usage: docker-updater setup [--dir /opt/" + product + "] | serve | status | upgrade --version vX.Y.Z | retry")
	}
	f := flag.NewFlagSet("docker-updater", flag.ContinueOnError)
	dir := f.String("dir", "/opt/"+product, "Compose working directory")
	v := f.String("version", "", "release tag")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	switch args[0] {
	case "setup":
		return setup(product, *dir)
	case "serve":
		p := filepath.Join(configDir(product), "config.json")
		if err := trusted(p); err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var c Config
		if err = json.Unmarshal(b, &c); err != nil {
			return err
		}
		if c.Product != product {
			return errors.New("product mismatch")
		}
		return serve(c)
	case "status":
		s := Check(context.Background(), product)
		if !s.Available {
			return errors.New("host updater is not running")
		}
		return json.NewEncoder(os.Stdout).Encode(s)
	case "upgrade":
		j, err := Request(context.Background(), product, *v)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(j)
	case "retry":
		return retry(product)

	default:
		return errors.New("unknown Docker updater command")
	}
}

func retry(product string) error {
	status := Check(context.Background(), product)
	if !status.Available || status.Job == nil || status.Job.Phase != "failed" {
		return errors.New("no failed job to retry")
	}
	if !strings.HasPrefix(status.Job.Error, "checking failed") && !strings.HasPrefix(status.Job.Error, "pulling failed") && !strings.HasPrefix(status.Job.Error, "backing_up failed") {
		return errors.New("container may have migrated data; inspect and recover the saved backup before clearing job.json manually")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	init, stop, start := "systemctl", "stop", "start"
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		init = "rc-service"
	}
	service := product + "-updater"
	run := func(action string) error {
		var err error
		if init == "systemctl" {
			_, err = command(ctx, init, action, service)
		} else {
			_, err = command(ctx, init, service, action)
		}
		return err
	}
	if err := run(stop); err != nil {
		return err
	}
	if err := saveJSON(filepath.Join(stateDir(product), "job.json"), Job{}); err != nil {
		_ = run(start)
		return err
	}
	if err := run(start); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		if Check(ctx, product).Available {
			j, err := Request(ctx, product, status.Job.Target)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(j)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("host updater did not restart")
}
