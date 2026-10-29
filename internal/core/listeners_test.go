package core

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func procFixture(t *testing.T, network, address, state, inode string) string {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "123")
	for _, dir := range []string{"fd", "net"} {
		if e := os.MkdirAll(filepath.Join(p, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(p, "stat"), []byte("123 (fake child) "+strings.Repeat("0 ", 19)+"42 0"), 0600)
	if e := os.Symlink("socket:[456]", filepath.Join(p, "fd", "3")); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(p, "net", network), []byte("header\n0: "+address+" 00000000:0000 "+state+" 0 0 0 0 0 "+inode+"\n"), 0600)
	return root
}
func TestListenerOwnershipRequiresTransportAddressAndInode(t *testing.T) {
	cases := []struct {
		name, network, address, state, inode, wantnet, wantaddr string
		good                                                    bool
	}{
		{"tcp", "tcp", "0100007F:1F90", "0A", "456", "tcp", "127.0.0.1", true},
		{"udp", "udp", "0100007F:1F90", "07", "456", "udp", "127.0.0.1", true},
		{"foreign owner", "tcp", "0100007F:1F90", "0A", "999", "tcp", "127.0.0.1", false},
		{"connected TCP", "tcp", "0100007F:1F90", "01", "456", "tcp", "127.0.0.1", false},
		{"connected UDP", "udp", "0100007F:1F90", "01", "456", "udp", "127.0.0.1", false},
		{"wrong transport", "tcp", "0100007F:1F90", "0A", "456", "udp", "127.0.0.1", false},
		{"wrong address", "tcp", "0100007F:1F90", "0A", "456", "tcp", "192.0.2.10", false},
		{"wildcard cannot be loopback", "tcp", "0100007F:1F90", "0A", "456", "tcp", "", false},
		{"wildcard", "tcp", "00000000:1F90", "0A", "456", "tcp", "", true},
		{"ipv6", "tcp6", "00000000000000000000000001000000:1F90", "0A", "456", "tcp", "::1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := procFixture(t, tc.network, tc.address, tc.state, tc.inode)
			e := checkListenersAt(root, map[string]int{"tag": 123}, []expectedListener{{"tag", tc.wantaddr, tc.wantnet, 8080}})
			if (e == nil) != tc.good {
				t.Fatalf("readiness %v wanted %v", e, tc.good)
			}
		})
	}
}
func TestExpectedListenerProtocolsAndEmptyAssignments(t *testing.T) {
	if len(expectedListeners(nil)) != 0 {
		t.Fatal("invented listeners for no-user/unused core")
	}
	in := []spec.Inbound{{Tag: "hy", Protocol: spec.Hysteria2, Port: 4000}, {Tag: "wg", Protocol: spec.WireGuard, Port: 4001}, {Tag: "m", Protocol: spec.Mieru, Port: 4002, MieruTransport: "BOTH"}, {Tag: "tls", Protocol: spec.Shadowsocks, Port: 4004, ShadowTLS: &spec.ShadowTLS{}}}
	got := expectedListeners(in)
	if len(got) != 5 || got[0].network != "udp" || got[1].network != "udp" || got[2].network != "tcp" || got[3].network != "udp" || got[3].port != 4003 || got[4].network != "tcp" {
		t.Fatalf("wrong transport expectations: %+v", got)
	}
	root := procFixture(t, "tcp", "00000000:1F90", "0A", "456")
	if e := checkListenersAt(root, map[string]int{"different": 123}, []expectedListener{{"tag", "", "tcp", 8080}}); e == nil {
		t.Fatal("another inbound's process certified readiness")
	}
}
func TestLinuxListenerOwnershipLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires real Linux procfs")
	}
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	for _, tc := range []struct {
		network string
		addr    net.Addr
	}{{"tcp", tcp.Addr()}, {"udp", udp.LocalAddr()}} {
		_, port, _ := net.SplitHostPort(tc.addr.String())
		n, _ := strconv.Atoi(port)
		w := expectedListener{"live", "127.0.0.1", tc.network, n}
		if e := checkListenersAt("/proc", map[string]int{"live": os.Getpid()}, []expectedListener{w}); e != nil {
			t.Fatal(e)
		}
		if e := checkListenersAt("/proc", map[string]int{"live": os.Getppid()}, []expectedListener{w}); e == nil {
			t.Fatal(fmt.Sprintf("foreign process accepted for %s", tc.network))
		}
	}
}
