package core

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// ListenerProcesses is optional: third-party adapters keep their existing API
// readiness contract. Built-in adapters expose supervisor-owned children only.
type ListenerProcesses interface{ ListenerPIDs() map[string]int }

type expectedListener struct {
	tag, address, network string
	port                  int
}

func expectedListeners(inbounds []spec.Inbound) []expectedListener {
	var out []expectedListener
	for _, ib := range inbounds {
		add := func(network string, port int) { out = append(out, expectedListener{ib.Tag, ib.Listen, network, port}) }
		if ib.ShadowTLS != nil {
			add("tcp", ib.Port)
			continue
		}
		switch ib.Protocol {
		case spec.Hysteria2, spec.TUIC, spec.WireGuard:
			add("udp", ib.Port)
		case spec.Mieru:
			switch strings.ToUpper(ib.MieruTransport) {
			case "UDP":
				add("udp", ib.Port)
			case "BOTH":
				add("tcp", ib.Port)
				add("udp", ib.Port+1)
			default:
				add("tcp", ib.Port)
			}
		case spec.Shadowsocks:
			add("tcp", ib.Port)
			add("udp", ib.Port)
		default:
			add("tcp", ib.Port)
		}
	}
	return out
}

// CheckListeners proves local socket ownership, not remote connectivity or
// subscriber authentication. Linux /proc supplies TCP and UDP evidence without
// attempting a counterfeit-prone connection to whichever process owns a port.
// Non-Linux platforms and external adapters retain their prior readiness check.
func CheckListeners(c Core, inbounds []spec.Inbound) error {
	p, ok := c.(ListenerProcesses)
	if !ok || runtime.GOOS != "linux" {
		return nil
	}
	if adapter, ok := c.(interface {
		ListenerInbounds([]spec.Inbound) []spec.Inbound
	}); ok {
		inbounds = adapter.ListenerInbounds(inbounds)
	}
	return checkListenersAt("/proc", p.ListenerPIDs(), expectedListeners(inbounds))
}
func checkListenersAt(root string, pids map[string]int, want []expectedListener) error {
	for _, w := range want {
		pid := pids[w.tag]
		if pid == 0 {
			pid = pids["*"]
		}
		if pid <= 0 {
			return fmt.Errorf("inbound %s has no supervised process", w.tag)
		}
		found, err := ownsListener(root, pid, w)
		if err != nil {
			return fmt.Errorf("inbound %s listener observation unavailable: %w", w.tag, err)
		}
		if !found {
			return fmt.Errorf("inbound %s expected %s listener is not owned by its process", w.tag, w.network)
		}
	}
	return nil
}
func ownsListener(root string, pid int, w expectedListener) (bool, error) {
	proc := filepath.Join(root, strconv.Itoa(pid))
	// Detect process replacement during observation; a reused numeric PID is not
	// evidence for the previous generation.
	before, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir(filepath.Join(proc, "fd"))
	if err != nil {
		return false, err
	}
	sockets := map[string]bool{}
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(proc, "fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			sockets[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	found := false
	for _, family := range []string{w.network, w.network + "6"} {
		f, err := os.Open(filepath.Join(proc, "net", family))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || !sockets[fields[9]] {
				continue
			}
			state := "0A"
			if w.network == "udp" {
				state = "07"
			}
			if fields[3] != state {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, e := strconv.ParseInt(parts[1], 16, 32)
			if e != nil || int(port) != w.port {
				continue
			}
			ip := procIP(parts[0])
			if ip == nil {
				continue
			}
			want := net.ParseIP(w.address)
			if w.address == "" {
				if !ip.IsUnspecified() {
					continue
				}
			} else if want == nil || !ip.Equal(want) {
				continue
			}
			found = true
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return false, err
		}
	}
	after, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return false, err
	}
	if processStart(before) == "" || processStart(before) != processStart(after) {
		return false, fmt.Errorf("process changed during listener observation")
	}
	return found, nil
}
func processStart(stat []byte) string {
	s := string(stat)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
func procIP(encoded string) net.IP {
	b, err := hex.DecodeString(encoded)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	// /proc renders native-endian u32 chunks, including for IPv6.
	for i := 0; i < len(b); i += 4 {
		v := binary.BigEndian.Uint32(b[i : i+4])
		binary.NativeEndian.PutUint32(b[i:i+4], v)
	}
	return net.IP(b)
}
