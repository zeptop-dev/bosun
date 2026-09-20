package shaper

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestApplyInstallsAndClears(t *testing.T) {
	k := newTC()
	s := k.shaper()
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tc qdisc replace dev eth0 root handle 1: htb default 0",
		"classid 1:8 htb rate 50mbit ceil 50mbit",
		"handle 0x10007 fw flowid 1:8",
		"dev ifb-bosun root",
		"action connmark action mirred egress redirect dev ifb-bosun",
		"ct mark set meta mark",
	} {
		if !strings.Contains(k.all(), want) {
			t.Fatalf("missing %q in\n%s", want, k.all())
		}
	}
	if st := s.Status(); !st.Supported || st.Users != 1 || st.Interface != "eth0" {
		t.Fatalf("status %+v", st)
	}
	n := len(k.cmds)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil || len(k.cmds) != n {
		t.Fatal("unchanged limits must be a no-op")
	}
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if tail := k.since(n); !strings.Contains(tail, "qdisc del dev eth0 root") || !strings.Contains(tail, "link del ifb-bosun") {
		t.Fatalf("clear: %s", tail)
	}
}

// Someone else already shapes the line (a VPS init script's HTB with an
// fq leaf): the per-user classes hang under their class, the root qdisc is
// left alone, and clearing the limits does not take their shaping with it.
func TestNestsUnderAForeignRootQdisc(t *testing.T) {
	k := newTC()
	k.lineShaper("eth0", "500Mbit")
	s := k.shaper()
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k.all(), "qdisc replace dev eth0 root") || strings.Contains(k.all(), "qdisc del dev eth0 root") {
		t.Fatalf("touched someone else's root qdisc:\n%s", k.all())
	}
	for _, want := range []string{
		"tc class replace dev eth0 parent 1:10 classid 1:8 htb rate 50mbit ceil 50mbit", // under their line class
		"tc filter replace dev eth0 parent 1: protocol all prio 1 handle 0x10007 fw flowid 1:8",
		"tc qdisc replace dev ifb-bosun root handle 1: htb default 0", // our own device, unchanged
	} {
		if !strings.Contains(k.all(), want) {
			t.Fatalf("missing %q in\n%s", want, k.all())
		}
	}
	if st := s.Status(); st.NestedUnder != "1:10" {
		t.Fatalf("status should say where it nested: %+v", st)
	}
	n := len(k.cmds)
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k.since(n), "qdisc del dev eth0 root") {
		t.Fatalf("clear removed someone else's shaping:\n%s", k.since(n))
	}
	if _, ok := k.classes["eth0"]["1:10"]; !ok {
		t.Fatal("the line class is gone")
	}
	if _, ok := k.classes["eth0"]["1:8"]; ok {
		t.Fatal("our user class stayed behind")
	}
	if len(k.filters["eth0"]) != 0 {
		t.Fatalf("our filters stayed behind: %v", k.filters["eth0"])
	}
}

// A user who loses their limit loses their class and their filter, even
// though the root qdisc is not ours to wipe.
func TestNestedApplyDropsStaleUserClasses(t *testing.T) {
	k := newTC()
	k.lineShaper("eth0", "500Mbit")
	s := k.shaper()
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}, {UserID: 9, Mbps: 20}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	gone := "1:" + strconv.FormatInt(spec.SpeedClass(9), 16)
	kept := "1:" + strconv.FormatInt(spec.SpeedClass(7), 16)
	if _, ok := k.classes["eth0"][gone]; ok {
		t.Fatal("the class of the user who lost their limit stayed")
	}
	if _, ok := k.classes["eth0"][kept]; !ok {
		t.Fatal("the remaining user lost their class")
	}
	for _, f := range k.filters["eth0"] {
		if strings.HasSuffix(f, gone) {
			t.Fatalf("a filter still points at the removed class: %s", f)
		}
	}
}

// Our own root (HTB with "default 0") is still replaced wholesale, and so
// is a plain fq root that nobody put there on purpose.
func TestTakesOverAnUnmanagedRoot(t *testing.T) {
	for _, root := range []simRoot{
		{kind: "fq", handle: "8001:"},
		{kind: "htb", handle: "8001:", def: "0"}, // an HTB of our shape, but not where we put ours
		{},
	} {
		k := newTC()
		if root.kind != "" {
			k.roots["eth0"] = root
		}
		s := k.shaper()
		if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
			t.Fatalf("root %+v: %v", root, err)
		}
		if !strings.Contains(k.all(), "tc qdisc replace dev eth0 root handle 1: htb default 0") {
			t.Fatalf("root %+v should be taken over:\n%s", root, k.all())
		}
		if !strings.Contains(k.all(), "tc class replace dev eth0 parent 1: classid 1:8") {
			t.Fatalf("root %+v: classes belong at the root:\n%s", root, k.all())
		}
	}
}

// Nesting turns the line class into an inner class, and HTB then shoves
// everything unclassified into its direct queue, unshaped and past the
// line cap. The shaper has to give that traffic a leaf of its own with
// the shaping the line class was doing, and hand the leaf back on the way
// out.
func TestNestingKeepsUnlimitedTrafficShaped(t *testing.T) {
	k := newTC()
	k.lineShaper("eth0", "100Mbit")
	s := k.shaper()
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tc class replace dev eth0 parent 1:10 classid 1:fffe htb rate 100Mbit ceil 100Mbit", // same cap as the line
		"tc qdisc replace dev eth0 parent 1:fffe handle fffe: fq maxrate 100Mbit",            // same pacing
		"tc filter replace dev eth0 parent 1: protocol all prio 900 u32 match u32 0 0 flowid 1:fffe",
	} {
		if !strings.Contains(k.all(), want) {
			t.Fatalf("missing %q in\n%s", want, k.all())
		}
	}
	n := len(k.cmds)
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.classes["eth0"]["1:fffe"]; ok {
		t.Fatal("the catch-all class stayed behind")
	}
	if got := k.qdiscs["eth0"]["1:10"]; !strings.Contains(got, "fq 100:") || !strings.Contains(got, "maxrate 100Mbit") {
		t.Fatalf("the line class did not get its leaf back: %q\n%s", got, k.since(n))
	}
}

// A restart does not clear the kernel, so the next apply meets its own
// work: an HTB root cannot be replaced in place (HTB has no change
// operation), and the classes of users whose limits went away while bosun
// was down have to go.
func TestSurvivesARestartWithLimitsInPlace(t *testing.T) {
	for _, line := range []bool{false, true} {
		k := newTC()
		if line {
			k.lineShaper("eth0", "500Mbit")
		}
		if err := k.shaper().Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}, {UserID: 9, Mbps: 20}}); err != nil {
			t.Fatal(err)
		}
		// A new Shaper: same kernel, no memory of what it holds.
		n := len(k.cmds)
		if err := k.shaper().Apply(context.Background(), []Limit{{UserID: 7, Mbps: 80}}); err != nil {
			t.Fatalf("line=%v: %v", line, err)
		}
		gone := "1:" + strconv.FormatInt(spec.SpeedClass(9), 16)
		if _, ok := k.classes["eth0"][gone]; ok {
			t.Fatalf("line=%v: a stale class survived the restart:\n%s", line, k.since(n))
		}
		if _, ok := k.classes["ifb-bosun"][gone]; ok {
			t.Fatalf("line=%v: a stale class survived on the ifb device:\n%s", line, k.since(n))
		}
		if got := k.classes["eth0"]["1:8"].rest; !strings.Contains(got, "80mbit") {
			t.Fatalf("line=%v: the new limit did not take: %q", line, got)
		}
		for _, f := range k.filters["eth0"] {
			if strings.HasSuffix(f, gone) {
				t.Fatalf("line=%v: a filter still points at the removed class: %s", line, f)
			}
		}
	}
}

// The ifb device outlives a restart too, and its root is ours to keep.
func TestRestartKeepsTheIFBRoot(t *testing.T) {
	k := newTC()
	if err := k.shaper().Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	n := len(k.cmds)
	if err := k.shaper().Apply(context.Background(), []Limit{{UserID: 7, Mbps: 60}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k.since(n), "qdisc del dev ifb-bosun root") {
		t.Fatalf("the ifb root was thrown away and rebuilt:\n%s", k.since(n))
	}
}

// A restart with no limits left to apply still has to clean up: the empty
// apply is the first one this process makes, and matching the zero value
// of what it last applied is not the same as knowing the kernel is clean.
func TestFirstEmptyApplyAfterARestartStillClears(t *testing.T) {
	k := newTC()
	k.lineShaper("eth0", "500Mbit")
	if err := k.shaper().Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	if err := k.shaper().Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.classes["eth0"]["1:8"]; ok {
		t.Fatal("a class from before the restart stayed")
	}
	if _, ok := k.classes["eth0"]["1:fffe"]; ok {
		t.Fatal("the catch-all from before the restart stayed")
	}
	if _, ok := k.classes["eth0"]["1:10"]; !ok {
		t.Fatal("the line class went with it")
	}
}

// Clearing throws away a root qdisc of ours, and only ours: an init
// script's fq (pacing the line for BBR) is not bosun's to remove, and
// bosun never put anything under it either.
func TestClearLeavesAForeignRootQdiscAlone(t *testing.T) {
	k := newTC()
	k.roots["eth0"] = simRoot{kind: "fq", handle: "8001:"}
	if err := k.shaper().Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := k.roots["eth0"]; got.kind != "fq" {
		t.Fatalf("the fq root was removed: %+v", got)
	}
}
