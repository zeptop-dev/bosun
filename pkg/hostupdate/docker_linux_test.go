//go:build linux

package hostupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run only inside scripts/test-lifecycle-linux.sh's private mount/PID namespace
// and disposable Docker daemon. It must never use a developer's Docker daemon.
func TestDockerLifecycle(t *testing.T) {
	root := os.Getenv("BOSUN_LIFECYCLE_FIXTURE")
	if root == "" {
		t.Skip("requires isolated Linux lifecycle fixture")
	}
	if os.Getenv("DOCKER_HOST") != "unix://"+root+"/docker.sock" {
		t.Fatal("refusing non-fixture Docker daemon")
	}
	ctx := context.Background()
	if _, err := fixtureCommand(ctx, "docker", "run", "--detach", "--name", "unrelated-fixture", "--network", "none", "--mount", "type=volume,src=unrelated-fixture-data,dst=/data", "alpine:3.24", "sleep", "600"); err != nil {
		t.Fatal(err)
	}
	defer fixtureCommand(ctx, "docker", "rm", "--force", "unrelated-fixture")
	for _, p := range []string{"captain", "bosun"} {
		t.Run(p, func(t *testing.T) {
			old, new := "v1.16.0", "v1.17.0"
			if p == "bosun" {
				old, new = "v0.64.3", "v0.65.0"
			}
			dir := "/opt/" + p
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			for _, v := range []string{old, new} {
				build := filepath.Join(root, p+"-"+v)
				_ = os.MkdirAll(build, 0755)
				b, err := os.ReadFile(filepath.Join(root, p+"-"+v+".bin"))
				if err != nil {
					t.Fatal(err)
				}
				_ = os.WriteFile(filepath.Join(build, p), b, 0755)
				dockerfile := "FROM alpine:3.24\nCOPY " + p + " /usr/local/bin/" + p + "\n"
				if p == "captain" {
					dockerfile += "RUN adduser -D -u 1000 captain && mkdir -p /var/lib/captain && chown captain /var/lib/captain\nUSER captain\n"
				}
				dockerfile += "ENV IN_CONTAINER=1\nENTRYPOINT [\"" + p + "\"]\n"
				_ = os.WriteFile(filepath.Join(build, "Dockerfile"), []byte(dockerfile), 0600)
				if _, err = fixtureCommand(ctx, "docker", "build", "-t", "zeptop/"+p+":"+v, build); err != nil {
					t.Fatal("build", p, v, err)
				}
			}
			cfg := "listen: 0.0.0.0:8080\nbase_url: http://localhost:8080\ndata_dir: /var/lib/captain\ndatabase:\n  driver: sqlite\n  dsn: /var/lib/captain/captain.db\ntls:\n  auto: false\n"
			mode := "serve"
			uid := 1000
			if p == "bosun" {
				cfg = "data_dir: /var/lib/bosun\npanel:\n  driver: local\nweb:\n  listen: 0.0.0.0:2053\ncores:\n  order: [singbox]\n  singbox: {binary: /bin/true}\n"
				mode = "run"
				uid = 0
			}
			_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600)
			_ = os.Chown(filepath.Join(dir, "config.yaml"), uid, uid)
			composeYAML := "services:\n  " + p + ":\n    image: zeptop/" + p + ":" + old + "\n    network_mode: none\n    command: [" + mode + ", -c, /etc/" + p + "/config.yaml]\n    volumes:\n      - ./config.yaml:/etc/" + p + "/config.yaml:ro\n      - " + p + "-data:/var/lib/" + p + "\nvolumes:\n  " + p + "-data:\n"
			_ = os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(composeYAML), 0600)
			if _, err := fixtureCommand(ctx, "docker", "compose", "--project-directory", dir, "up", "-d"); err != nil {
				t.Fatal("initial compose", err)
			}
			if err := setup(p, dir); err != nil {
				t.Fatal("register", err)
			}
			var c Config
			b, err := os.ReadFile(filepath.Join(configDir(p), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			h := &host{c: c, dir: stateDir(p), release: func(context.Context, string) error { return nil }, run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				// Test images exist only in the disposable daemon; all other Docker
				// commands, readiness checks and filesystem operations are real.
				if name == "docker" && len(args) > 0 && args[0] == "pull" {
					return nil, nil
				}
				return fixtureCommand(ctx, name, args...)
			}}
			ln, err := net.Listen("unix", socket(p))
			if err != nil {
				t.Fatal(err)
			}
			_ = os.Chown(socket(p), c.UID, c.UID)
			_ = os.Chmod(socket(p), 0600)
			srv := &http.Server{Handler: h.handler()}
			go srv.Serve(ln)
			defer srv.Close()
			deadline := time.Now().Add(time.Minute)
			for {
				id, _, e := h.current(ctx)
				if e == nil {
					_, e = fixtureCommand(ctx, "docker", "exec", id, p, "healthcheck", "--version", old)
				}
				if e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("old application not ready", e)
				}
				time.Sleep(time.Second)
			}
			j, err := Request(ctx, p, new)
			if err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(3 * time.Minute)
			for {
				s := Check(ctx, p)
				if s.Job != nil && !s.Job.Active() {
					if s.Job.Phase != "complete" {
						t.Fatalf("upgrade: %+v", s.Job)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("upgrade timeout")
				}
				time.Sleep(time.Second)
			}
			if _, err = os.Stat(filepath.Join(stateDir(p), "backups", j.ID, "data")); err != nil {
				t.Fatal("missing data backup", err)
			}
			id, v, err := h.current(ctx)
			if err != nil || v != new {
				t.Fatalf("new runtime: %s %v", v, err)
			}
			b, err = fixtureCommand(ctx, "docker", "inspect", "--format", "{{json .Mounts}}", id)
			if err != nil || strings.Contains(string(b), "docker.sock") {
				t.Fatal("Docker socket exposed", err)
			}
			// A normal compose invocation must retain the newly pinned image.
			if _, err = fixtureCommand(ctx, "docker", "compose", "--project-directory", dir, "up", "-d"); err != nil {
				t.Fatal(err)
			}
			_, v, err = h.current(ctx)
			if err != nil || v != new {
				t.Fatal("manual compose reverted version", v, err)
			}
			if _, err = fixtureCommand(ctx, "docker", "run", "--detach", "--name", "shared-consumer", "--network", "none", "--mount", "type=volume,src="+p+"_"+p+"-data,dst=/data", "alpine:3.24", "sleep", "600"); err != nil {
				t.Fatal(err)
			}
			if err = uninstall(ctx, p, dir, false, fixtureCommand, nil); err == nil {
				t.Fatal("removed shared application data")
			}
			if _, err = fixtureCommand(ctx, "docker", "inspect", id); err != nil {
				t.Fatal("shared-volume refusal deleted application", err)
			}
			if _, err = fixtureCommand(ctx, "docker", "rm", "--force", "shared-consumer"); err != nil {
				t.Fatal(err)
			}
			_ = srv.Close()
			if err = uninstall(ctx, p, dir, false, fixtureCommand, nil); err != nil {
				t.Fatal("full uninstall", err)
			}
			if b, err = fixtureCommand(ctx, "docker", "inspect", "--format", "{{.State.Running}}", "unrelated-fixture"); err != nil || strings.TrimSpace(string(b)) != "true" {
				t.Fatal("unrelated container changed", err)
			}
			for _, path := range []string{dir, configDir(p), stateDir(p), "/usr/local/lib/" + p + "-updater"} {
				if _, err = os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("leftover", path, err)
				}
			}
			b, err = fixtureCommand(ctx, "docker", "volume", "ls", "--format", "{{.Name}}")
			if err != nil || strings.Contains(string(b), p+"-data") {
				t.Fatal("data volume left behind", err)
			}
		})
	}
}

func fixtureCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("fixture command %s %v: %v; stdout: %s", name, args, err, b)
	}
	return b, nil
}
