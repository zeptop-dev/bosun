package captain

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func TestConsumedRevisionsDoNotBorrowWatcherState(t *testing.T) {
	f := &fakeCaptain{t: t, token: "test-token", state: agentproto.State{Revision: "first"}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, PairCode: "GOOD-CODE", TokenFile: filepath.Join(t.TempDir(), "token")}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	assert := func(node, forwards string) {
		t.Helper()
		n, f := c.ConsumedRevisions()
		if n != node || f != forwards {
			t.Fatalf("consumed (%q, %q), want (%q, %q)", n, f, node, forwards)
		}
	}
	if _, _, err := c.Node(ctx); err != nil {
		t.Fatal(err)
	}
	assert("", "") // no coherent node/users snapshot until Users is consumed
	_, _, _ = c.Users(ctx)
	_, _, _ = c.Forwards(ctx)
	assert("first", "first")
	// Simulate a long-poll fetch during the old revision's apply.
	f.state.Revision = "second"
	if _, err := c.fetchWait(ctx, ""); err != nil {
		t.Fatal(err)
	}
	assert("first", "first")
	if _, err := c.Report(ctx, agentproto.Report{AppliedRevision: "first"}); err != nil {
		t.Fatal(err)
	}
	if rep := f.reports[0]; rep.Revision != "second" || rep.AppliedRevision != "first" {
		t.Fatal("latest fetch overwrote the agent's apply acknowledgment", rep)
	}
	// Mixed consumption must never advertise the newer state as applied.
	_, _, _ = c.Users(ctx)
	assert("", "first")
	_, _, _ = c.Forwards(ctx)
	assert("", "second")
	if _, _, err := c.Node(ctx); err != nil {
		t.Fatal(err)
	}
	assert("second", "second")
	if _, err := c.Report(ctx, agentproto.Report{}); err != nil {
		t.Fatal(err)
	}
	if rep := f.reports[1]; rep.AppliedRevision != "" {
		t.Fatal("driver manufactured an apply acknowledgment", rep)
	}
}
