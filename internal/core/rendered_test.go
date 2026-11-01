package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

var renderedAt = time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)

func renderedFixture(t *testing.T, key byte) *RenderedTracker {
	t.Helper()
	r := &RenderedTracker{entropy: bytes.NewReader(bytes.Repeat([]byte{key}, 32))}
	r.Activate("xray", "*", map[string][]byte{"config.json": []byte(`{"password":"private-password"}`)}, map[string]uint64{"*": 41}, renderedAt)
	r.Accept([]string{"*"})
	if r.Snapshot("xray", map[string]uint64{"*": 41}) == nil {
		t.Fatal("fixture activation missing")
	}
	return r
}

func TestRenderedArtifactPrivacyAndLocalKeys(t *testing.T) {
	processes := map[string]uint64{"private-inbound-tag": 91}
	files := map[string][]byte{"/private/cert-store/config.json": []byte(`{"password":"private-password"}`)}
	var first, second RenderedTracker
	for _, r := range []*RenderedTracker{&first, &second} {
		r.Activate("xray", "private-part-name", files, processes, renderedAt)
		r.Accept([]string{"private-part-name"})
	}
	a, b := first.Snapshot("xray", processes), second.Snapshot("xray", processes)
	if a == nil || b == nil || a.Digest == b.Digest {
		t.Fatal("independent cryptographic keys did not separate artifact identity")
	}
	if err := agentproto.ValidateRenderedConfigReport(&agentproto.RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []agentproto.RenderedArtifact{*a}}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private", "password", "inbound", "generation", "config.json"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("private material escaped into artifact: %s", secret)
		}
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 9 {
		t.Fatal("artifact added fields outside the privacy allowlist", err)
	}
	// Input mutation after Activate cannot change either stored file evidence
	// or stored process identities, and returned DTOs do not alias the tracker.
	files["/private/cert-store/config.json"][0] = '!'
	processes["private-inbound-tag"] = 92
	delete(files, "/private/cert-store/config.json")
	a.Digest = "changed"
	again := first.Snapshot("xray", map[string]uint64{"private-inbound-tag": 91})
	if again == nil || again.Digest == "changed" || again.Files != 1 {
		t.Fatal("artifact retained mutable input/output references")
	}
}

func TestRenderedDigestFramingOrderingAndFormat(t *testing.T) {
	makeArtifact := func(coreName string, files map[string][]byte, parts []string) *agentproto.RenderedArtifact {
		t.Helper()
		r := &RenderedTracker{entropy: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
		for _, part := range parts {
			r.Activate(coreName, part, files, map[string]uint64{part: uint64(part[0])}, renderedAt)
		}
		r.Accept(parts)
		p := map[string]uint64{}
		for _, part := range parts {
			p[part] = uint64(part[0])
		}
		return r.Snapshot(coreName, p)
	}
	a := makeArtifact("xray", map[string][]byte{"b": []byte("two"), "a": []byte("one")}, []string{"second", "first"})
	b := makeArtifact("xray", map[string][]byte{"a": []byte("one"), "b": []byte("two")}, []string{"first", "second"})
	if a == nil || b == nil || a.Digest != b.Digest || a.Files != 4 || a.Processes != 2 {
		t.Fatal("artifact depends on map or part insertion order")
	}
	c := makeArtifact("xray", map[string][]byte{"a": []byte("bc")}, []string{"part"})
	d := makeArtifact("xray", map[string][]byte{"ab": []byte("c")}, []string{"part"})
	if c.Digest == d.Digest {
		t.Fatal("unframed names/content permit ambiguous file identity")
	}
	for name, format := range map[string]string{"xray": "json", "singbox": "json", "singbox-extended": "json", "mita": "json", "hysteria": "yaml", "snell": "ini"} {
		t.Run(name, func(t *testing.T) {
			a := makeArtifact(name, map[string][]byte{"private": []byte("config")}, []string{"part"})
			if a == nil || a.Format != format {
				t.Fatal("incorrect allowlisted core format")
			}
		})
	}
}

func TestRenderedActivationRuntimeUpdatesAndNoop(t *testing.T) {
	r := renderedFixture(t, 1)
	p := map[string]uint64{"*": 41}
	before := *r.Snapshot("xray", p)
	r.Invalidate()
	if r.Snapshot("xray", p) != nil {
		t.Fatal("in-progress apply retained accepted evidence")
	}
	r.RuntimeUpdate("*")
	if r.Snapshot("xray", p) != nil {
		t.Fatal("runtime update bypassed complete acceptance")
	}
	r.Accept([]string{"*"})
	updated := r.Snapshot("xray", p)
	if updated == nil || !updated.RuntimeUpdates || updated.Digest != before.Digest || !updated.ActivatedAt.Equal(before.ActivatedAt) {
		t.Fatal("runtime update changed activation file identity")
	}
	r.Activate("xray", "*", map[string][]byte{"config.json": []byte(`{"password":"private-password"}`)}, p, renderedAt.Add(time.Minute))
	r.Accept([]string{"*"})
	if got := r.Snapshot("xray", p); got == nil || *got != *updated {
		t.Fatal("no-op retry refreshed activation or forgot runtime changes")
	}
	// Restart changes the activation even when the file bytes are identical.
	p["*"]++
	restartedAt := renderedAt.Add(2 * time.Minute)
	r.Activate("xray", "*", map[string][]byte{"config.json": []byte(`{"password":"private-password"}`)}, p, restartedAt)
	r.Accept([]string{"*"})
	got := r.Snapshot("xray", p)
	if got == nil || got.RuntimeUpdates || !got.ActivatedAt.Equal(restartedAt) || got.Digest != before.Digest {
		t.Fatal("restart did not reset the activation boundary")
	}
	r.Activate("xray", "*", map[string][]byte{"config.json": []byte(`{"password":"replacement"}`)}, p, restartedAt.Add(time.Second))
	r.Accept([]string{"*"})
	if changed := r.Snapshot("xray", p); changed == nil || changed.Digest == before.Digest {
		t.Fatal("accepted new bytes retained old artifact identity")
	}
	// An adapter may explicitly establish a new activation boundary without
	// replacing the child (for example, a full proxy cycle inside mita).
	r.RuntimeUpdate("*")
	r.Accept([]string{"*"})
	r.Forget("*")
	cycledAt := restartedAt.Add(2 * time.Second)
	r.Activate("xray", "*", map[string][]byte{"config.json": []byte(`{"password":"replacement"}`)}, p, cycledAt)
	r.Accept([]string{"*"})
	if cycled := r.Snapshot("xray", p); cycled == nil || cycled.RuntimeUpdates || !cycled.ActivatedAt.Equal(cycledAt) {
		t.Fatal("explicit full activation retained the prior runtime boundary")
	}
}

func TestRenderedCompletePartsPartialFailureAndForget(t *testing.T) {
	var r RenderedTracker
	files := map[string][]byte{"config.json": []byte("{}")}
	r.Activate("mita", "a", files, map[string]uint64{"a": 1}, renderedAt)
	r.Accept([]string{"a", "b"})
	if r.Snapshot("mita", map[string]uint64{"a": 1}) != nil {
		t.Fatal("partial multipart activation appeared complete")
	}
	r.RuntimeUpdate("b")
	r.Accept([]string{"a", "b"})
	if r.Snapshot("mita", map[string]uint64{"a": 1, "b": 2}) != nil {
		t.Fatal("runtime update created evidence for an unactivated part")
	}
	r.Activate("mita", "b", files, map[string]uint64{"b": 2}, renderedAt.Add(time.Minute))
	r.RuntimeUpdate("b")
	r.Accept([]string{"b", "a"})
	got := r.Snapshot("mita", map[string]uint64{"a": 1, "b": 2})
	if got == nil || got.Files != 2 || got.Processes != 2 || !got.RuntimeUpdates || !got.ActivatedAt.Equal(renderedAt) {
		t.Fatal("multipart aggregation lost earliest activation or runtime flag")
	}
	r.Forget("a")
	r.Accept([]string{"a", "b"})
	if r.Snapshot("mita", map[string]uint64{"a": 1, "b": 2}) != nil {
		t.Fatal("forgotten or failed part was reaccepted without activation")
	}
	r.Accept([]string{"b"})
	got = r.Snapshot("mita", map[string]uint64{"b": 2})
	if got == nil || got.Files != 1 || !got.ActivatedAt.Equal(renderedAt.Add(time.Minute)) {
		t.Fatal("removal did not retain independent successful part")
	}
	r.Accept(nil)
	r.Accept([]string{"b"})
	if r.Snapshot("mita", map[string]uint64{"b": 2}) != nil {
		t.Fatal("removed parts reappeared without a new activation")
	}
}

func TestRenderedProcessIdentityDeathReplacementAndExactSet(t *testing.T) {
	for _, observed := range []map[string]uint64{nil, {}, {"*": 0}, {"*": 42}, {"other": 41}, {"*": 41, "unexpected": 99}} {
		r := renderedFixture(t, 2)
		if r.Snapshot("xray", observed) != nil {
			t.Fatal("absent/replaced/extra process retained current evidence", observed)
		}
		if r.Snapshot("xray", map[string]uint64{"*": 41}) != nil {
			t.Fatal("process mismatch automatically recovered without acceptance")
		}
		if observed["*"] != 41 {
			r.Accept([]string{"*"})
			if r.Snapshot("xray", map[string]uint64{"*": 41}) != nil {
				t.Fatal("dead activation resurrected by reusing old identity")
			}
		}
	}
	r := renderedFixture(t, 3)
	if r.Snapshot("singbox", map[string]uint64{"*": 41}) != nil {
		t.Fatal("different adapter borrowed evidence")
	}
	var shared RenderedTracker
	shared.Activate("mita", "a", map[string][]byte{"a": []byte("a")}, map[string]uint64{"a": 1}, renderedAt)
	shared.Activate("mita", "b", map[string][]byte{"b": []byte("b")}, map[string]uint64{"b": 1}, renderedAt)
	shared.Accept([]string{"a", "b"})
	if got := shared.Snapshot("mita", map[string]uint64{"a": 1, "b": 1}); got == nil || got.Processes != 1 {
		t.Fatal("multiple tags counted the same process twice")
	}
}

func TestRenderedRejectsInvalidActivationAndEntropy(t *testing.T) {
	for _, kind := range []string{"core", "part", "files", "empty file", "filename", "processes", "generation", "time", "short entropy"} {
		t.Run(kind, func(t *testing.T) {
			r := &RenderedTracker{entropy: bytes.NewReader(bytes.Repeat([]byte{9}, 32))}
			coreName, part := "xray", "*"
			files, processes, at := map[string][]byte{"config": []byte("{}")}, map[string]uint64{"*": 1}, renderedAt
			switch kind {
			case "core":
				coreName = "unknown-private-core"
			case "part":
				part = ""
			case "files":
				files = nil
			case "empty file":
				files["config"] = nil
			case "filename":
				files = map[string][]byte{"": []byte("config")}
			case "processes":
				processes = nil
			case "generation":
				processes["*"] = 0
			case "time":
				at = time.Time{}
			case "short entropy":
				r.entropy = bytes.NewReader([]byte{1})
			}
			r.Activate(coreName, part, files, processes, at)
			r.Accept([]string{part})
			if r.Snapshot(coreName, processes) != nil {
				t.Fatal("invalid activation produced evidence")
			}
			if kind == "short entropy" {
				if r.keyReady || r.secret != [32]byte{} {
					t.Fatal("partial entropy retained as a fallback key")
				}
				r.entropy = bytes.NewReader(bytes.Repeat([]byte{3}, 32))
				r.Accept([]string{part})
				if r.Snapshot(coreName, processes) != nil {
					t.Fatal("acceptance fabricated entropy-failed activation")
				}
				r.Activate(coreName, part, files, processes, at)
				r.Accept([]string{part})
				if r.Snapshot(coreName, processes) == nil {
					t.Fatal("fresh successful entropy could not activate")
				}
			}
		})
	}
	r := renderedFixture(t, 2)
	r.Activate("xray", "*", nil, map[string]uint64{"*": 41}, renderedAt)
	r.Accept([]string{"*"})
	if r.Snapshot("xray", map[string]uint64{"*": 41}) != nil {
		t.Fatal("failed replacement retained old part")
	}
}

func TestRenderedAggregateBoundsAndDuplicateAcceptance(t *testing.T) {
	var r RenderedTracker
	files := make(map[string][]byte, renderedLimit)
	for i := range renderedLimit {
		files[fmt.Sprint(i)] = []byte("x")
	}
	r.Activate("mita", "a", files, map[string]uint64{"a": 1}, renderedAt)
	r.Accept([]string{"a"})
	if got := r.Snapshot("mita", map[string]uint64{"a": 1}); got == nil || got.Files != renderedLimit {
		t.Fatal("valid boundary rejected")
	}
	r.Activate("mita", "b", map[string][]byte{"b": []byte("x")}, map[string]uint64{"b": 2}, renderedAt)
	r.Accept([]string{"a", "b"})
	if r.Snapshot("mita", map[string]uint64{"a": 1, "b": 2}) != nil {
		t.Fatal("aggregate file bound exceeded")
	}
	r.Accept([]string{"b"})
	if r.Snapshot("mita", map[string]uint64{"b": 2}) != nil {
		t.Fatal("over-budget activation was retained")
	}
	r.Activate("mita", "b", map[string][]byte{"b": []byte("x")}, map[string]uint64{"b": 2}, renderedAt)
	r.Accept([]string{"b"})
	if r.Snapshot("mita", map[string]uint64{"b": 2}) == nil {
		t.Fatal("pruned reactivation could not recover")
	}
	r.Accept([]string{"b", "b"})
	if r.Snapshot("mita", map[string]uint64{"b": 2}) != nil {
		t.Fatal("duplicate accepted part")
	}
	files["extra"] = []byte("x")
	r.Activate("mita", "b", files, map[string]uint64{"b": 2}, renderedAt)
	r.Accept([]string{"b"})
	if r.Snapshot("mita", map[string]uint64{"b": 2}) != nil {
		t.Fatal("individual file bound exceeded")
	}
	tooMany := make(map[string]uint64, renderedLimit+1)
	for i := range renderedLimit + 1 {
		tooMany[fmt.Sprint(i)] = uint64(i + 1)
	}
	r.Activate("mita", "b", map[string][]byte{"b": []byte("x")}, tooMany, renderedAt)
	r.Accept([]string{"b"})
	if r.Snapshot("mita", tooMany) != nil {
		t.Fatal("process bound exceeded")
	}
}

func TestRenderedProcessObservationRejectsRaces(t *testing.T) {
	for _, kind := range []string{"stable", "missing", "zero pid", "empty name", "replaced", "exited", "pid changed", "late pid changed", "late generation changed"} {
		t.Run(kind, func(t *testing.T) {
			pidReads, generationReads := 0, 0
			pids := func() map[string]int {
				pidReads++
				v := map[string]int{"tag": 100}
				if kind == "zero pid" {
					v["tag"] = 0
				}
				if kind == "empty name" {
					v = map[string]int{"": 100}
				}
				if kind == "pid changed" && pidReads >= 2 || kind == "late pid changed" && pidReads >= 3 {
					v["tag"] = 101
				}
				return v
			}
			generations := func() map[int]uint64 {
				generationReads++
				v := map[int]uint64{100: 1, 101: 2}
				if kind == "missing" || kind == "exited" && generationReads >= 2 {
					delete(v, 100)
				}
				if kind == "replaced" && generationReads >= 2 || kind == "late generation changed" && generationReads >= 3 {
					v[100] = 3
				}
				return v
			}
			got := renderedProcesses(pids, generations)
			if kind == "stable" {
				if !maps.Equal(got, map[string]uint64{"tag": 1}) {
					t.Fatal("stable supervised process rejected")
				}
			} else if got != nil {
				t.Fatal("unsafe process observation accepted", kind)
			}
		})
	}
	if RenderedProcesses(fakeCore{}) != nil || RenderedProcessSet(nil) != nil || RenderedProcessSet(map[string]int{"absent": -1}) != nil {
		t.Fatal("external or missing processes fabricated evidence")
	}
}

func TestRenderedTrackerConcurrentReadersAndWriters(t *testing.T) {
	r := renderedFixture(t, 1)
	files, processes := map[string][]byte{"config.json": []byte(`{"password":"private-password"}`)}, map[string]uint64{"*": 41}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for range 100 {
				switch worker % 4 {
				case 0:
					r.Invalidate()
					r.Activate("xray", "*", files, processes, renderedAt)
					r.Accept([]string{"*"})
				case 1:
					r.RuntimeUpdate("*")
					r.Accept([]string{"*"})
				case 2:
					r.Forget("*")
				case 3:
					if got := r.Snapshot("xray", processes); got != nil {
						if err := agentproto.ValidateRenderedConfigReport(&agentproto.RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []agentproto.RenderedArtifact{*got}}); err != nil {
							t.Error(err)
						}
					}
				}
			}
		})
	}
	wg.Wait()
	r.Activate("xray", "*", files, processes, renderedAt)
	r.Accept([]string{"*"})
	if r.Snapshot("xray", processes) == nil {
		t.Fatal("concurrent invalidation prevented a final known activation")
	}
}
