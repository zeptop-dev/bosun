package hostupdate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpgradeKeepsDeploymentAndVerifiesApplication(t *testing.T) {
	h, calls := fixture(t, "")
	h.execute(h.job)
	if h.job.Phase != "complete" {
		t.Fatalf("job: %+v", h.job)
	}
	joined := strings.Join(*calls, "\n")
	for _, want := range []string{"docker pull zeptop/captain:v1.17.0", "docker stop --time 60 old", "docker cp old:/var/lib/captain", "--no-deps --pull never captain", "healthcheck --version v1.17.0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	if strings.Index(joined, "docker pull") > strings.Index(joined, "docker stop") {
		t.Fatal("stopped before download")
	}
	base, _ := os.ReadFile(h.c.Files[0])
	if string(base) != "operator deployment\n" {
		t.Fatal("base compose overwritten")
	}
	b, _ := os.ReadFile(overridePath(h.c))
	if !strings.Contains(string(b), "sha256:") {
		t.Fatal("image not pinned")
	}
	if strings.Contains(string(b), "docker.sock") {
		t.Fatal("application received Docker socket")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "backups", h.job.ID, "deployment-0")); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeFailuresDoNotLaunchOldImageAfterMigration(t *testing.T) {
	for _, stage := range []string{"pull", "backup", "recreate", "readiness"} {
		t.Run(stage, func(t *testing.T) {
			h, calls := fixture(t, stage)
			h.execute(h.job)
			if h.job.Phase != "failed" {
				t.Fatalf("job: %+v", h.job)
			}
			joined := strings.Join(*calls, "\n")
			if stage == "pull" && strings.Contains(joined, "docker stop") {
				t.Fatal("download failure interrupted application")
			}
			resumed := strings.Contains(joined, "docker start old")
			if resumed != (stage == "backup") {
				t.Fatalf("unsafe/missing recovery: %s", joined)
			}
			if strings.Contains(h.job.Error, "secret") {
				t.Fatal("command stderr leaked")
			}
			var saved Job
			b, _ := os.ReadFile(filepath.Join(h.dir, "job.json"))
			if json.Unmarshal(b, &saved) != nil || saved.Phase != "failed" {
				t.Fatal("failure not persisted")
			}
		})
	}
}

func TestUpgradeRejectsDowngradeAndUnpublishedRelease(t *testing.T) {
	for _, kind := range []string{"downgrade", "unpublished", "untrusted"} {
		t.Run(kind, func(t *testing.T) {
			h, calls := fixture(t, "")
			switch kind {
			case "downgrade":
				h.job.Target = "v1.15.0"
			case "unpublished":
				h.release = func(context.Context, string) error { return errors.New("draft") }
			case "untrusted":
				h.validate = func(Config) error { return errors.New("writable deployment") }
			}
			h.execute(h.job)
			if h.job.Phase != "failed" || strings.Contains(strings.Join(*calls, "\n"), "docker pull") {
				t.Fatalf("unsafe job: %+v %v", h.job, *calls)
			}
		})
	}
}

func TestSocketAPIRejectsCommandsAndDeduplicatesJobs(t *testing.T) {
	h, _ := fixture(t, "")
	h.job = Job{ID: "busy", Target: "v1.17.0", Phase: "pulling"}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"version":"v1.17.0"}`, 202}, {`{"version":"v1.18.0"}`, 409},
		{`{"version":"v1.17.0","command":"rm"}`, 400}, {`{"version":"v1.17.0;id"}`, 400},
		{`{"version":"v1.17.0"} {}`, 400}, {`{"version":"latest"}`, 400},
	} {
		w := httptest.NewRecorder()
		h.handler().ServeHTTP(w, httptest.NewRequest("POST", "/upgrade", strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Errorf("%s: %d", tc.body, w.Code)
		}
	}
	h.job.Phase = "failed"
	w := httptest.NewRecorder()
	h.handler().ServeHTTP(w, httptest.NewRequest("POST", "/upgrade", strings.NewReader(`{"version":"v1.17.0"}`)))
	if w.Code != 409 {
		t.Fatal("periodic agent retry would repeat destructive upgrade")
	}
}

func TestAtomicRejectsSymlinkAndKeepsPrivatePermissions(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	link := filepath.Join(d, "link")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if atomic(link, []byte("bad"), 0600) == nil {
		t.Fatal("followed symlink")
	}
	if err := saveJSON(target, Job{ID: "id"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(target)
	if st.Mode().Perm() != 0600 {
		t.Fatal("exposed job state")
	}
}

func TestVersionOrder(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{{"v1.17.0", "v1.16.0", true}, {"v1.16.0", "v1.17.0", false}, {"v1.17.0", "v1.17.0", false}, {"v1.2.3;id", "v1.0.0", false}, {"v9999999999999999999.0.0", "v1.0.0", false}} {
		if newer(tc.a, tc.b) != tc.want {
			t.Fatal(tc)
		}
	}
}

func fixture(t *testing.T, fail string) (*host, *[]string) {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "compose.yaml")
	_ = os.WriteFile(base, []byte("operator deployment\n"), 0600)
	c := Config{Product: "captain", Dir: dir, Project: "captain", Files: []string{base}, Repository: "zeptop/captain", UID: 1000}
	_ = os.WriteFile(overridePath(c), override(c, "zeptop/captain:v1.16.0"), 0600)
	calls := []string{}
	var mu sync.Mutex
	recreated := false
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case strings.Contains(line, "docker pull"):
			if fail == "pull" {
				return nil, errors.New("secret registry failure")
			}
		case strings.Contains(line, "image inspect"):
			return []byte("sha256:" + strings.Repeat("a", 64)), nil
		case strings.Contains(line, "docker run"):
			return []byte("captain v1.17.0"), nil
		case strings.Contains(line, " ps "):
			if recreated {
				return []byte("new\n"), nil
			}
			return []byte("old\n"), nil
		case strings.Contains(line, "exec old captain version"):
			return []byte("captain v1.16.0\n"), nil
		case strings.Contains(line, "docker cp"):
			if strings.Contains(line, ":/etc/captain/config.yaml") {
				return nil, os.WriteFile(args[len(args)-1], []byte("data_dir: /var/lib/captain\n"), 0600)
			}
			if fail == "backup" {
				return nil, errors.New("secret path failure")
			}
		case strings.Contains(line, " up "):
			recreated = true
			if fail == "recreate" {
				return nil, errors.New("new image may have migrated the DB")
			}
		case strings.Contains(line, "healthcheck"):
			if fail == "readiness" {
				return nil, errors.New("old version still serving")
			}
		}
		return nil, nil
	}
	h := &host{c: c, run: run, dir: dir, job: Job{ID: "job1", Target: "v1.17.0", Phase: "queued"}, release: func(context.Context, string) error { return nil }, validate: func(Config) error { return nil }, verifyTimeout: 10 * time.Millisecond}
	return h, &calls
}

func TestBackupRejectsStateOutsideDataVolume(t *testing.T) {
	for _, raw := range []string{"data_dir: /srv/data", "database: {dsn: /srv/panel.db}", "web: {state_file: /var/lib/captain/../../outside.json}", "panel: {captain: {token_file: /etc/token}}"} {
		if standardLayout("captain", []byte(raw)) == nil {
			t.Fatal("accepted incomplete backup", raw)
		}
	}
	if err := standardLayout("captain", []byte("data_dir: /var/lib/captain\ndatabase: {dsn: /var/lib/captain/captain.db}")); err != nil {
		t.Fatal(err)
	}
}
