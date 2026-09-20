package shaper

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestApplyInstallsAndClears(t *testing.T) {
	var cmds []string
	s := &Shaper{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "ip" && len(args) > 2 && args[2] == "get" {
			return []byte("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.30 uid 0"), nil
		}
		return nil, nil
	}}
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"tc qdisc replace dev eth0 root handle 1: htb default 0", "classid 1:8 htb rate 50mbit ceil 50mbit", "handle 0x10007 fw flowid 1:8", "dev ifb-bosun root", "action connmark action mirred egress redirect dev ifb-bosun", "ct mark set meta mark"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if st := s.Status(); !st.Supported || st.Users != 1 || st.Interface != "eth0" {
		t.Fatalf("status %+v", st)
	}
	n := len(cmds)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil || len(cmds) != n {
		t.Fatal("unchanged limits must be a no-op")
	}
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if tail := strings.Join(cmds[n:], "\n"); !strings.Contains(tail, "qdisc del dev eth0 root") || !strings.Contains(tail, "link del ifb-bosun") {
		t.Fatalf("clear: %s", tail)
	}
}

// fakeTC answers the two queries the shaper makes about the interface and
// records every command.
func fakeTC(t *testing.T, rootQdisc, classes string) (*Shaper, *[]string) {
	t.Helper()
	var cmds []string
	s := &Shaper{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		switch {
		case name == "ip" && len(args) > 2 && args[2] == "get":
			return []byte("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.30 uid 0"), nil
		case name == "tc" && len(args) > 1 && args[0] == "qdisc" && args[1] == "show":
			if len(args) > 3 && args[3] == ifbDev {
				return nil, nil
			}
			return []byte(rootQdisc), nil
		case name == "tc" && len(args) > 1 && args[0] == "class" && args[1] == "show":
			return []byte(classes), nil
		}
		return nil, nil
	}}
	return s, &cmds
}

// Someone else already shapes the line (a VPS init script's HTB with an
// fq leaf): the per-user classes hang under their class, the root qdisc is
// left alone, and clearing the limits does not take their shaping with it.
func TestNestsUnderAForeignRootQdisc(t *testing.T) {
	root := "qdisc htb 1: root refcnt 2 r2q 10 default 0x10 direct_packets_stat 0 ver 3.17\n"
	classes := "class htb 1:10 root leaf 100: prio 0 rate 500Mbit ceil 500Mbit burst 250000b cburst 250000b\n"
	s, cmds := fakeTC(t, root, classes)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*cmds, "\n")
	if strings.Contains(joined, "qdisc replace dev eth0 root") {
		t.Fatalf("replaced someone else's root qdisc:\n%s", joined)
	}
	for _, want := range []string{
		"tc class replace dev eth0 parent 1:10 classid 1:8 htb rate 50mbit ceil 50mbit", // under their line class
		"tc filter replace dev eth0 parent 1: protocol all prio 1 handle 0x10007 fw flowid 1:8",
		"tc qdisc replace dev ifb-bosun root handle 1: htb default 0", // our own device, unchanged
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if st := s.Status(); st.NestedUnder != "1:10" {
		t.Fatalf("status should say where it nested: %+v", st)
	}
	n := len(*cmds)
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	tail := strings.Join((*cmds)[n:], "\n")
	if strings.Contains(tail, "qdisc del dev eth0 root") {
		t.Fatalf("clear removed someone else's shaping:\n%s", tail)
	}
	for _, want := range []string{"tc class del dev eth0 classid 1:8", "handle 0x10007 fw", "link del ifb-bosun"} {
		if !strings.Contains(tail, want) {
			t.Fatalf("clear should remove our own pieces, missing %q in\n%s", want, tail)
		}
	}
}

// A user who loses their limit loses their class, even though the root
// qdisc is not ours to wipe.
func TestNestedApplyDropsStaleUserClasses(t *testing.T) {
	root := "qdisc htb 1: root refcnt 2 r2q 10 default 0x10\n"
	classes := "class htb 1:10 root leaf 100: prio 0 rate 500Mbit ceil 500Mbit\n"
	s, cmds := fakeTC(t, root, classes)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}, {UserID: 9, Mbps: 20}}); err != nil {
		t.Fatal(err)
	}
	n := len(*cmds)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	tail := strings.Join((*cmds)[n:], "\n")
	gone := "tc class del dev eth0 classid 1:" + strconv.FormatInt(spec.SpeedClass(9), 16)
	if !strings.Contains(tail, gone) {
		t.Fatalf("the class of the user who lost their limit stayed:\n%s", tail)
	}
	if strings.Contains(tail, "classid 1:"+strconv.FormatInt(spec.SpeedClass(7), 16)+" htb rate 50mbit") == false {
		t.Fatalf("the remaining user should keep their class:\n%s", tail)
	}
}

// Our own root (HTB with "default 0") is still replaced wholesale, and so
// is a plain fq root that nobody put there on purpose.
func TestTakesOverItsOwnOrAnUnmanagedRoot(t *testing.T) {
	for _, root := range []string{
		"qdisc htb 1: root refcnt 2 r2q 10 default 0 direct_packets_stat 0\n",
		"qdisc fq 8001: root refcnt 2 limit 10000p flow_limit 100p\n",
		"",
	} {
		s, cmds := fakeTC(t, root, "")
		if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(*cmds, "\n")
		if !strings.Contains(joined, "tc qdisc replace dev eth0 root handle 1: htb default 0") {
			t.Fatalf("root %q should be taken over:\n%s", root, joined)
		}
		if !strings.Contains(joined, "tc class replace dev eth0 parent 1: classid 1:8") {
			t.Fatalf("root %q: classes belong at the root:\n%s", root, joined)
		}
	}
}
