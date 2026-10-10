package hostupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Product    string   `json:"product"`
	Dir        string   `json:"dir"`
	Project    string   `json:"project"`
	Files      []string `json:"files"`
	Repository string   `json:"repository"`
	UID        int      `json:"uid"`
}

func configDir(p string) string    { return "/etc/" + p + "-updater" }
func stateDir(p string) string     { return "/var/lib/" + p + "-updater" }
func overridePath(c Config) string { return filepath.Join(c.Dir, "compose.updater.yaml") }

type runner func(context.Context, string, ...string) ([]byte, error)

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	// Never forward Docker output: compose config/inspect can contain secrets.
	b, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("%s command failed", name)
	}
	return b, nil
}

func compose(ctx context.Context, run runner, c Config, args ...string) ([]byte, error) {
	a := []string{"compose", "--project-directory", c.Dir, "--project-name", c.Project}
	for _, f := range c.Files {
		a = append(a, "--file", f)
	}
	a = append(a, "--file", overridePath(c))
	return run(ctx, "docker", append(a, args...)...)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomic(path, append(b, '\n'), 0600)
}

func atomic(path string, b []byte, mode os.FileMode) error {
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return errors.New("refusing non-regular output")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".updater-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func override(c Config, image string) []byte {
	// JSON is valid YAML; encoding also prevents interpolation/syntax injection.
	v := map[string]any{"services": map[string]any{c.Product: map[string]any{
		"image":   image,
		"volumes": []map[string]any{{"type": "bind", "source": filepath.Dir(socket(c.Product)), "target": filepath.Dir(socket(c.Product)), "read_only": true}},
	}}}
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

type host struct {
	c             Config
	run           runner
	mu            sync.Mutex
	job           Job
	dir           string
	release       func(context.Context, string) error
	validate      func(Config) error
	verifyTimeout time.Duration
}

func (h *host) persist(j Job) error { return saveJSON(filepath.Join(h.dir, "job.json"), j) }
func (h *host) stage(phase, message string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	j := h.job
	j.Phase = phase
	j.Error = message
	j.UpdatedAt = time.Now().UTC()
	if err := h.persist(j); err != nil {
		return err
	}
	h.job = j
	return nil
}

func (h *host) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		s := Status{Available: true}
		if h.job.ID != "" {
			j := h.job
			s.Job = &j
		}
		_ = json.NewEncoder(w).Encode(s)
	})
	m.HandleFunc("POST /upgrade", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Version string `json:"version"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || !tagRE.MatchString(in.Version) || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		h.mu.Lock()
		if h.job.Active() {
			j := h.job
			h.mu.Unlock()
			if j.Target != in.Version {
				http.Error(w, "upgrade in progress", 409)
				return
			}
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(j)
			return
		}
		// Failed requests are not silently retried by periodic managed pulls.
		// An explicit host `retry` or a different target is required.
		if h.job.Phase == "failed" && h.job.Target == in.Version {
			h.mu.Unlock()
			http.Error(w, "previous upgrade failed; inspect and retry on host", 409)
			return
		}
		var id [12]byte
		_, err := rand.Read(id[:])
		if err != nil {
			h.mu.Unlock()
			http.Error(w, "cannot create job", 500)
			return
		}
		j := Job{ID: hex.EncodeToString(id[:]), Target: in.Version, Phase: "queued", UpdatedAt: time.Now().UTC()}
		if err = h.persist(j); err != nil {
			h.mu.Unlock()
			http.Error(w, "cannot save job", 500)
			return
		}
		h.job = j
		h.mu.Unlock()
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(j)
		go h.execute(j)
	})
	return m
}

func (h *host) current(ctx context.Context) (string, string, error) {
	b, err := compose(ctx, h.run, h.c, "ps", "--all", "--quiet", h.c.Product)
	if err != nil {
		return "", "", err
	}
	ids := strings.Fields(string(b))
	if len(ids) != 1 {
		return "", "", errors.New("expected one registered application container")
	}
	b, err = h.run(ctx, "docker", "exec", ids[0], h.c.Product, "version")
	if err != nil {
		return "", "", err
	}
	words := strings.Fields(string(b))
	if len(words) != 2 || words[0] != h.c.Product || !tagRE.MatchString(words[1]) {
		return "", "", errors.New("current container is not an official release")
	}
	return ids[0], words[1], nil
}

func (h *host) execute(j Job) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	phase := "checking"
	stopped := false
	backupComplete := false
	startedNew := false
	var oldID string
	err := func() error {
		if err := h.stage(phase, ""); err != nil {
			return err
		}
		validate := h.validate
		if validate == nil {
			validate = validateConfig
		}
		if err := validate(h.c); err != nil {
			return err
		}
		id, current, err := h.current(ctx)
		if err != nil {
			return err
		}
		oldID = id
		if err = containerLayout(ctx, h.run, h.c.Product, id); err != nil {
			return err
		}
		if !newer(j.Target, current) {
			return errors.New("target must be newer than running version")
		}
		h.mu.Lock()
		h.job.Previous = current
		h.mu.Unlock()
		if err = h.release(ctx, j.Target); err != nil {
			return err
		}
		phase = "pulling"
		if err = h.stage(phase, ""); err != nil {
			return err
		}
		image := h.c.Repository + ":" + j.Target
		if _, err = h.run(ctx, "docker", "pull", image); err != nil {
			return err
		}
		b, err := h.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image)
		if err != nil {
			return err
		}
		pinned := strings.TrimSpace(string(b))
		if !imageIDRE.MatchString(pinned) {
			return errors.New("invalid image ID")
		}
		b, err = h.run(ctx, "docker", "run", "--rm", "--network", "none", "--entrypoint", "/usr/local/bin/"+h.c.Product, pinned, "version")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(b)) != h.c.Product+" "+j.Target {
			return errors.New("image version mismatch")
		}
		phase = "backing_up"
		if err = h.stage(phase, ""); err != nil {
			return err
		}
		backup := filepath.Join(h.dir, "backups", j.ID)
		if err = os.MkdirAll(backup, 0700); err != nil {
			return err
		}
		// Persist the exact deployment inputs before stopping, without exposing
		// secrets to the application or replacing operator-owned compose files.
		for i, f := range append(append([]string{}, h.c.Files...), overridePath(h.c), filepath.Join(h.c.Dir, ".env")) {
			b, err = os.ReadFile(f)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if err = atomic(filepath.Join(backup, fmt.Sprintf("deployment-%d", i)), b, 0600); err != nil {
				return err
			}
		}
		if _, err = h.run(ctx, "docker", "stop", "--time", "60", id); err != nil {
			return err
		}
		stopped = true
		if _, err = h.run(ctx, "docker", "cp", id+":/var/lib/"+h.c.Product, filepath.Join(backup, "data")); err != nil {
			return err
		}
		if _, err = h.run(ctx, "docker", "cp", id+":/etc/"+h.c.Product, filepath.Join(backup, "config")); err != nil {
			return err
		}
		if err = syncTree(backup); err != nil {
			return err
		}
		backupComplete = true
		phase = "recreating"
		if err = h.stage(phase, ""); err != nil {
			return err
		}
		if err = atomic(overridePath(h.c), override(h.c, pinned), 0600); err != nil {
			return err
		}
		// From this point a new process may have applied database migrations.
		// Never automatically launch the older image against this data.
		startedNew = true
		if _, err = compose(ctx, h.run, h.c, "up", "--detach", "--no-deps", "--pull", "never", h.c.Product); err != nil {
			return err
		}
		phase = "verifying"
		if err = h.stage(phase, ""); err != nil {
			return err
		}
		verifyCtx, done := context.WithTimeout(ctx, h.verificationTimeout())
		defer done()
		for {
			b, err = compose(verifyCtx, h.run, h.c, "ps", "--quiet", h.c.Product)
			ids := strings.Fields(string(b))
			if err == nil && len(ids) == 1 && ids[0] != oldID {
				_, err = h.run(verifyCtx, "docker", "exec", ids[0], h.c.Product, "healthcheck", "--version", j.Target)
				if err == nil {
					return h.stage("complete", "")
				}
			}
			select {
			case <-verifyCtx.Done():
				return errors.New("target application did not become ready")
			case <-time.After(2 * time.Second):
			}
		}
	}()
	if err != nil {
		if stopped && !startedNew {
			if !backupComplete {
				_ = os.RemoveAll(filepath.Join(h.dir, "backups", j.ID, "data"))
				_ = os.RemoveAll(filepath.Join(h.dir, "backups", j.ID, "config"))
			}
			recovery, done := context.WithTimeout(context.Background(), time.Minute)
			_, _ = h.run(recovery, "docker", "start", oldID)
			done()
		}
		_ = h.stage("failed", phase+" failed; inspect the host updater and its saved backup before retrying")
	}
}

func officialRelease(product string) func(context.Context, string) error {
	return func(ctx context.Context, tag string) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/zeptop-dev/"+product+"/releases/tags/"+tag, nil)
		if err != nil {
			return err
		}
		r.Header.Set("Accept", "application/vnd.github+json")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		var v struct {
			Tag        string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v) != nil || v.Tag != tag || v.Draft || v.Prerelease {
			return errors.New("target is not a published stable release")
		}
		return nil
	}
}

func serve(c Config) error {
	if err := validateConfig(c); err != nil {
		return err
	}
	dir := stateDir(c.Product)
	if err := ownedDir(dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "worker.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("host updater is already running")
	}
	var j Job
	if b, err := os.ReadFile(filepath.Join(dir, "job.json")); err == nil {
		if err = json.Unmarshal(b, &j); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	h := &host{c: c, run: command, dir: dir, job: j, release: officialRelease(c.Product)}
	if j.Active() {
		if err := h.stage("failed", "host updater interrupted; inspect container and backup before retrying"); err != nil {
			return err
		}
	}
	path := socket(c.Product)
	if err := ownedDir(filepath.Dir(path), 0711); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err = os.Chown(path, c.UID, c.UID); err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	srv := &http.Server{Handler: h.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	return srv.Serve(ln)
}

func (h *host) verificationTimeout() time.Duration {
	if h.verifyTimeout > 0 {
		return h.verifyTimeout
	}
	return 2 * time.Minute
}

// Flush copied data before starting a process that might migrate it. Symlinks
// are archived as links; never follow one outside the private backup tree.
func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}
