package captain

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/boyang-hu/bosun/pkg/agentproto"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// fakeCaptain implements the three agent endpoints in memory.
type fakeCaptain struct {
	t        *testing.T
	token    string
	state    agentproto.State
	reports  []agentproto.Report
	pairUsed bool
}

func (f *fakeCaptain) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent/pair", func(w http.ResponseWriter, r *http.Request) {
		var in agentproto.PairRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Code != "GOOD-CODE" || f.pairUsed {
			http.Error(w, `{"error":"invalid"}`, http.StatusNotFound)
			return
		}
		f.pairUsed = true
		_ = json.NewEncoder(w).Encode(agentproto.PairResponse{NodeID: "1", Token: f.token})
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+f.token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/agent/state", auth(func(w http.ResponseWriter, r *http.Request) {
		etag := `"` + f.state.Revision + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(f.state)
	}))
	mux.HandleFunc("POST /api/agent/report", auth(func(w http.ResponseWriter, r *http.Request) {
		var rep agentproto.Report
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.reports = append(f.reports, rep)
		_ = json.NewEncoder(w).Encode(agentproto.ReportResponse{StateChanged: rep.Revision != f.state.Revision})
	}))
	return mux
}

func TestPairFetchReport(t *testing.T) {
	f := &fakeCaptain{t: t, token: "tok-1", state: agentproto.State{
		Revision: "r1", PullSeconds: 7, PushSeconds: 9,
		Node:     spec.Node{ID: "1", Inbounds: []spec.Inbound{{Tag: "a", Protocol: spec.Mieru, Port: 1, ScopedUsers: true, Users: []spec.User{{ID: 2, Name: "u2"}}}}},
		Users:    []spec.User{{ID: 1, Name: "u1"}},
		Forwards: []spec.Forward{{Tag: "f", Port: 5, Protocol: "tcp", Target: "1.2.3.4:5"}},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "captain.token")

	c, err := New(Config{URL: srv.URL, PairCode: "GOOD-CODE", TokenFile: tokenFile, Version: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, changed, err := c.Node(ctx)
	if err != nil || !changed || node.ID != "1" || len(node.Forwards) != 1 || !node.Inbounds[0].ScopedUsers {
		t.Fatalf("node: %+v %v %v", node, changed, err)
	}
	if b, _ := os.ReadFile(tokenFile); string(b) != "tok-1\n" {
		t.Fatalf("token not persisted: %q", b)
	}
	users, changed, _ := c.Users(ctx)
	if !changed || len(users) != 1 || users[0].ID != 1 {
		t.Fatalf("users: %+v %v", users, changed)
	}
	fw, changed, _ := c.Forwards(ctx)
	if !changed || len(fw) != 1 {
		t.Fatalf("forwards: %+v %v", fw, changed)
	}
	if iv := c.Intervals(); iv.Pull.Seconds() != 7 || iv.Push.Seconds() != 9 {
		t.Fatalf("intervals: %+v", iv)
	}
	// Unchanged revision: 304 and no change on any accessor.
	if _, changed, _ := c.Node(ctx); changed {
		t.Fatal("node should be unchanged")
	}
	if _, changed, _ := c.Users(ctx); changed {
		t.Fatal("users should be unchanged")
	}
	// Report carries the applied revision; a newer panel revision flags a change.
	if sc, err := c.Report(ctx, agentproto.Report{Traffic: []spec.UserTraffic{{UserID: 1, Up: 1, Down: 2}}}); err != nil || sc {
		t.Fatalf("report: %v %v", sc, err)
	}
	if f.reports[0].Revision != "r1" || f.reports[0].Version != "test" || f.reports[0].Traffic[0].UserID != 1 {
		t.Fatalf("report body: %+v", f.reports[0])
	}
	f.state.Revision = "r2"
	if sc, _ := c.Report(ctx, agentproto.Report{}); !sc {
		t.Fatal("report should flag state change")
	}
	if node, changed, _ := c.Node(ctx); !changed || node == nil {
		t.Fatal("node should change after r2")
	}

	// A second client reuses the stored token without pairing.
	c2, err := New(Config{URL: srv.URL, TokenFile: tokenFile}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c2.Node(ctx); err != nil {
		t.Fatalf("stored token: %v", err)
	}
	if _, err := New(Config{URL: srv.URL, TokenFile: filepath.Join(t.TempDir(), "none")}, slog.Default()); err == nil {
		t.Fatal("no token and no code must fail")
	}
}
