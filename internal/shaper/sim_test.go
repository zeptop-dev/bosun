package shaper

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// tcSim stands in for the parts of tc the shaper talks to. It answers the
// queries out of state the shaper's own commands change, so a test runs
// into the same rules the kernel imposes — an HTB root qdisc that cannot
// be replaced in place, a class that loses its leaf qdisc the moment it
// gains a child — instead of a fixed string that always agrees.
type tcSim struct {
	cmds    []string
	roots   map[string]simRoot
	qdiscs  map[string]map[string]string // dev -> parent -> qdisc line
	classes map[string]map[string]simClass
	filters map[string]map[string]string // dev -> "prio/handle" -> filter line
}

type simRoot struct{ kind, handle, def string }

type simClass struct{ parent, rest string }

func newTC() *tcSim {
	return &tcSim{
		roots:   map[string]simRoot{},
		qdiscs:  map[string]map[string]string{},
		classes: map[string]map[string]simClass{},
		filters: map[string]map[string]string{},
	}
}

func val(args []string, key string) string {
	for i, a := range args {
		if a == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func has(args []string, key string) bool {
	for _, a := range args {
		if a == key {
			return true
		}
	}
	return false
}

func (r simRoot) String() string {
	if r.kind == "" {
		return ""
	}
	if r.kind != "htb" {
		return "qdisc " + r.kind + " " + r.handle + " root refcnt 2 limit 10000p"
	}
	return "qdisc htb " + r.handle + " root refcnt 2 r2q 10 default 0x" + r.def + " direct_packets_stat 0"
}

func (k *tcSim) wipe(dev string) {
	delete(k.roots, dev)
	delete(k.qdiscs, dev)
	delete(k.classes, dev)
	delete(k.filters, dev)
}

// renderClass prints a class the way "tc class show" does: a class with a
// child has no leaf qdisc of its own, and one hanging off the root qdisc
// says "root" rather than naming a parent.
func (k *tcSim) renderClass(dev, cls string, c simClass) string {
	where := "parent " + c.parent
	if strings.HasSuffix(c.parent, ":") {
		where = "root"
	}
	leaf := ""
	if q, ok := k.qdiscs[dev][cls]; ok {
		leaf = " leaf " + strings.Fields(q)[2]
	}
	return "class htb " + cls + " " + where + leaf + " prio 0 " + c.rest
}

func (k *tcSim) run(_ context.Context, name string, args ...string) ([]byte, error) {
	k.cmds = append(k.cmds, name+" "+strings.Join(args, " "))
	switch name {
	case "ip":
		if len(args) > 2 && args[2] == "get" {
			return []byte("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.30 uid 0"), nil
		}
		if len(args) > 2 && args[0] == "link" && args[1] == "del" {
			k.wipe(args[2])
		}
		return nil, nil
	case "tc":
	default:
		return nil, nil
	}
	dev := val(args, "dev")
	if args[0] == "filter" && has(args, "ingress") {
		return nil, nil // the ingress qdisc is a world of its own
	}
	switch args[0] + " " + args[1] {
	case "qdisc show":
		if has(args, "root") {
			return []byte(k.roots[dev].String()), nil
		}
		lines := []string{k.roots[dev].String()}
		for _, q := range sortedValues(k.qdiscs[dev]) {
			lines = append(lines, q)
		}
		return []byte(strings.Join(lines, "\n")), nil

	case "qdisc del":
		if has(args, "root") {
			k.wipe(dev)
		}
		return nil, nil

	case "qdisc replace", "qdisc add":
		if has(args, "ingress") {
			return nil, nil
		}
		handle := val(args, "handle")
		if has(args, "root") {
			kind := args[len(args)-1]
			def := "0"
			if i := indexOf(args, "default"); i >= 0 {
				kind, def = args[i-1], args[i+1]
			} else if i := indexOf(args, "handle"); i >= 0 {
				kind = args[i+2]
			}
			// HTB has no qdisc-level change operation: tc cannot replace
			// one HTB root with another under the same handle.
			if old := k.roots[dev]; old.kind == "htb" && kind == "htb" && old.handle == handle {
				return []byte("Error: Change operation not supported by specified qdisc."), errors.New("exit status 2")
			}
			k.wipe(dev)
			k.roots[dev] = simRoot{kind: kind, handle: handle, def: strings.TrimPrefix(def, "0x")}
			return nil, nil
		}
		parent := val(args, "parent")
		i := indexOf(args, "parent") + 2
		if args[i] == "handle" {
			i += 2
		}
		if handle == "" {
			handle = "8000:"
		}
		line := "qdisc " + args[i] + " " + handle + " parent " + parent
		if rest := strings.Join(args[i+1:], " "); rest != "" {
			line += " " + rest
		}
		set(k.qdiscs, dev)[parent] = line
		return nil, nil

	case "class replace":
		parent, cls := val(args, "parent"), val(args, "classid")
		if !strings.HasSuffix(parent, ":") {
			// A class that gains a child stops being a leaf, and the
			// kernel throws the qdisc that was under it away.
			delete(k.qdiscs[dev], parent)
		}
		set(k.classes, dev)[cls] = simClass{parent: parent, rest: strings.Join(args[indexOf(args, "htb")+1:], " ")}
		return nil, nil

	case "class del":
		delete(k.classes[dev], val(args, "classid"))
		return nil, nil

	case "class show":
		var lines []string
		for _, cls := range sortedKeys(k.classes[dev]) {
			lines = append(lines, k.renderClass(dev, cls, k.classes[dev][cls]))
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil

	case "filter replace", "filter add":
		prio, handle, flow, parent := val(args, "prio"), val(args, "handle"), val(args, "flowid"), val(args, "parent")
		line := "filter parent " + parent + " protocol all pref " + prio
		if has(args, "fw") {
			line += " fw chain 0 handle " + handle + " classid " + flow
		} else {
			line += " u32 chain 0 fh 800::800 flowid " + flow
		}
		set(k.filters, dev)[prio+"/"+handle] = line
		return nil, nil

	case "filter del":
		prio, handle := val(args, "prio"), val(args, "handle")
		for key := range k.filters[dev] {
			if strings.HasPrefix(key, prio+"/") && (handle == "" || key == prio+"/"+handle) {
				delete(k.filters[dev], key)
			}
		}
		return nil, nil

	case "filter show":
		return []byte(strings.Join(sortedValues(k.filters[dev]), "\n")), nil
	}
	return nil, nil
}

func indexOf(args []string, key string) int {
	for i, a := range args {
		if a == key {
			return i
		}
	}
	return -1
}

func set[V any](m map[string]map[string]V, dev string) map[string]V {
	if m[dev] == nil {
		m[dev] = map[string]V{}
	}
	return m[dev]
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, m[k])
	}
	return out
}

// lineShaper puts a quench-style cap on the interface: an HTB root whose
// unclassified traffic goes to a line class with an fq leaf pacing it.
func (k *tcSim) lineShaper(dev, rate string) {
	ctx := context.Background()
	_, _ = k.run(ctx, "tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "10")
	_, _ = k.run(ctx, "tc", "class", "replace", "dev", dev, "parent", "1:", "classid", "1:10", "htb", "rate", rate, "ceil", rate)
	_, _ = k.run(ctx, "tc", "qdisc", "replace", "dev", dev, "parent", "1:10", "handle", "100:", "fq", "maxrate", rate)
	k.cmds = nil
}

// since returns everything run after mark, as one string.
func (k *tcSim) since(mark int) string { return strings.Join(k.cmds[mark:], "\n") }

func (k *tcSim) all() string { return strings.Join(k.cmds, "\n") }

// shaper is a Shaper wired to this kernel.
func (k *tcSim) shaper() *Shaper { return &Shaper{Run: k.run} }
