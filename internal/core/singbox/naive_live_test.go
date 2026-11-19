package singbox

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Exercise the public padding framing with an independent HTTP/2 client.
// This is a protocol fixture, not a Chromium fingerprint verification.
func TestRealSingboxNaiveAccountingAndRevocation(t *testing.T) {
	bin := compatibilityBinary(t)
	cp, kp := compatibilityCert(t)
	cert, _ := os.ReadFile(cp)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var leases []net.Listener
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		leases = append(leases, l)
		return l.Addr().(*net.TCPAddr).Port
	}
	ins := []spec.Inbound{{Tag: "naive-a", Protocol: spec.Naive, Listen: "127.0.0.1", Port: port(), TLS: &spec.TLS{Mode: spec.TLSStandard, CertPath: cp, KeyPath: kp}}, {Tag: "naive-b", Protocol: spec.Naive, Listen: "127.0.0.1", Port: port(), TLS: &spec.TLS{Mode: spec.TLSStandard, CertPath: cp, KeyPath: kp}}}
	stats := net.JoinHostPort("127.0.0.1", strconv.Itoa(port()))
	for _, l := range leases {
		l.Close()
	}
	c, err := New(Options{Binary: bin, WorkDir: t.TempDir(), StatsListen: stats}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop(context.Background())
	node := &spec.Node{AllowPrivateDest: true, Inbounds: ins}
	b, err := c.Render(node, ins, users)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx, b); err != nil {
		t.Fatal(err)
	}
	ready := func() {
		t.Helper()
		for until := time.Now().Add(4 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
			conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ins[0].Port), 100*time.Millisecond)
			if e == nil {
				conn.Close()
				return
			}
		}
		t.Fatal("core not ready")
	}
	ready()
	payload := bytes.Repeat([]byte("naive-echo"), 1000)
	transfer := func(ib spec.Inbound, u spec.User) error {
		return naiveTestTransfer(ctx, pool, net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port)), echo.Addr().String(), u, payload)
	}

	for _, ib := range ins {
		for _, u := range users {
			if err = transfer(ib, u); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Receiving the echoed payload does not synchronize with the server's
	// post-Write counter update. Observe without consuming counters until
	// both users and both inbounds have accounted for the completed transfers.
	for deadline := time.Now().Add(3 * time.Second); ; {
		current, e := c.Stats(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		inbound, e := c.InboundStats(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		complete := true
		for _, u := range users {
			v := current[u.Name]
			complete = complete && v.Up >= int64(2*len(payload)) && v.Down >= int64(2*len(payload))
		}
		for _, ib := range ins {
			v := inbound[ib.Tag]
			complete = complete && v.Up >= int64(2*len(payload)) && v.Down >= int64(2*len(payload))
		}
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters did not converge: users=%v inbounds=%v", current, inbound)
		}
		t.Logf("waiting for completed-transfer counters: users=%v inbounds=%v", current, inbound)
		time.Sleep(20 * time.Millisecond)
	}
	totals, err := c.Stats(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		v := totals[u.Name]
		if v.Up < int64(2*len(payload)) || v.Down < int64(2*len(payload)) {
			t.Fatalf("missing user totals: %v", totals)
		}
		for key := range totals {
			if key == spec.InboundUser(u.Name, ins[1].Tag) {
				t.Fatal("aggregate assigned to last inbound")
			}
		}
	}
	byInbound, err := c.InboundStats(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, ib := range ins {
		if byInbound[ib.Tag].Up < int64(2*len(payload)) {
			t.Fatalf("missing inbound stats: %v", byInbound)
		}
	}
	zero, err := c.Stats(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range zero {
		if v.Up != 0 || v.Down != 0 {
			t.Fatalf("reset: %v", zero)
		}
	}
	b, err = c.Render(node, ins, users[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	ready()
	if err = transfer(ins[0], users[1]); err == nil {
		t.Fatal("revoked user connected")
	}
	if err = transfer(ins[0], users[0]); err != nil {
		t.Fatal(err)
	}
}
