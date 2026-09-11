package local

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gitlab.com/boyang-hu/bosun/pkg/agentproto"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
	"log/slog"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, pw, err := Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if pw == "" || !s.Login("admin", pw) {
		t.Fatal("initial password should work")
	}
	return s
}

func TestStoreLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "a", Protocol: spec.VLESS, Port: 443}, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "b", Protocol: spec.Trojan, Port: 443}, Enabled: true}, ""); err == nil {
		t.Fatal("port clash should be rejected")
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "h", Protocol: spec.Hysteria2, Port: 443}, Enabled: true}, ""); err != nil {
		t.Fatalf("udp protocol may share the port number: %v", err)
	}
	u1, err := s.CreateUser(User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.CreateUser(User{Name: "bob", Enabled: true, InboundTags: []string{"h"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Changed():
	default:
		t.Fatal("mutations should wake the agent")
	}

	node, changed, err := s.Node(ctx)
	if err != nil || !changed || len(node.Inbounds) != 2 {
		t.Fatalf("node: %+v %v %v", node, changed, err)
	}
	users, changed, _ := s.Users(ctx)
	if !changed || len(users) != 2 {
		t.Fatalf("users: %+v", users)
	}
	for _, ib := range node.Inbounds {
		switch ib.Tag {
		case "a":
			if !ib.ScopedUsers || len(ib.Users) != 1 || ib.Users[0].ID != u1.ID {
				t.Fatalf("inbound a should be scoped to alice: %+v", ib)
			}
		case "h":
			if !ib.ScopedUsers || len(ib.Users) != 2 {
				t.Fatalf("inbound h should carry both: %+v", ib)
			}
		}
	}
	if _, changed, _ := s.Node(ctx); changed {
		t.Fatal("unchanged revision must not report a change")
	}

	// Traffic accounting and quota exhaustion.
	if err := s.UpdateUser(User{ID: u2.ID, Name: "bob", Enabled: true, QuotaBytes: 100, InboundTags: []string{"h"}}); err != nil {
		t.Fatal(err)
	}
	s.Node(ctx)
	stateChanged, err := s.Report(ctx, agentproto.Report{Traffic: []spec.UserTraffic{{UserID: u2.ID, Up: 60, Down: 50}}, Online: map[string][]string{u2.UUID: {"1.2.3.4"}}})
	if err != nil || !stateChanged {
		t.Fatalf("quota crossing should request a re-pull: %v %v", stateChanged, err)
	}
	got, _ := s.User(u2.ID)
	if got.Up != 60 || got.Down != 50 || got.Usable(time.Now()) {
		t.Fatalf("accounting: %+v", got)
	}
	node, _, _ = s.Node(ctx)
	users, _, _ = s.Users(ctx)
	for _, ib := range node.Inbounds {
		// Only alice is left and she is unrestricted, so scoping collapses
		// back to the node-level list.
		if ib.Tag == "h" && (ib.ScopedUsers || len(users) != 1 || users[0].ID != u1.ID) {
			t.Fatalf("over-quota user must be dropped: %+v %+v", ib, users)
		}
	}
	if s.Runtime().Online[u2.UUID][0] != "1.2.3.4" {
		t.Fatal("online IPs should be kept")
	}

	// Persistence.
	s2, _, err := Open(s.path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.ListUsers()) != 2 || len(s2.Inbounds()) != 2 {
		t.Fatal("state should persist")
	}

	// Takeover and detach with the snapshot restored.
	if err := s.Adopt("https://captain.example"); err != nil {
		t.Fatal(err)
	}
	if mode, m, snap := s.Mode(); mode != ModeManaged || m.URL != "https://captain.example" || snap == nil || len(snap.Inbounds) != 2 {
		t.Fatalf("adopt: %v %+v %+v", mode, m, snap)
	}
	if len(s.Inbounds()) != 0 {
		t.Fatal("local objects should be cleared while managed")
	}
	select {
	case m := <-s.ModeChanges():
		if m != ModeManaged {
			t.Fatal(m)
		}
	default:
		t.Fatal("mode change should be signalled")
	}
	if err := s.Detach(nil); err != nil {
		t.Fatal(err)
	}
	if mode, _, snap := s.Mode(); mode != ModeLocal || snap != nil || len(s.Inbounds()) != 2 || len(s.ListUsers()) != 2 {
		t.Fatalf("detach should restore the snapshot: %v", mode)
	}

	// Detach keeping the managed state instead.
	_ = s.Adopt("https://captain.example")
	st := &agentproto.State{Node: spec.Node{Inbounds: []spec.Inbound{{Tag: "m", Protocol: spec.Mieru, Port: 24450}}},
		Users: []spec.User{{ID: 7, Name: "u", UUID: "11111111-1111-4111-8111-111111111111", Password: "11111111-1111-4111-8111-111111111111"}}}
	if err := s.Detach(st); err != nil {
		t.Fatal(err)
	}
	if ibs := s.Inbounds(); len(ibs) != 1 || ibs[0].Tag != "m" || !ibs[0].Enabled {
		t.Fatalf("keep: %+v", ibs)
	}
	if us := s.ListUsers(); len(us) != 1 || us[0].UUID != st.Users[0].UUID || us[0].Password != "" {
		t.Fatalf("keep users: %+v", us)
	}
}
