package singbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/http2"
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
		callCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		tr := &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
		defer tr.CloseIdleConnections()
		rd, wr := io.Pipe()
		defer rd.Close()
		defer wr.Close()
		req, _ := http.NewRequestWithContext(callCtx, "CONNECT", fmt.Sprintf("https://127.0.0.1:%d", ib.Port), rd)
		req.Host = echo.Addr().String()
		req.Header.Set("Padding", "fixture-padding")
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Name+":"+u.Password)))
		res, e := tr.RoundTrip(req)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("CONNECT status %d", res.StatusCode)
		}
		go func() {
			frame := make([]byte, 3+len(payload))
			binary.BigEndian.PutUint16(frame, uint16(len(payload)))
			copy(frame[3:], payload)
			_, e := wr.Write(frame)
			if e != nil {
				wr.CloseWithError(e)
			}
		}()
		got := []byte{}
		for len(got) < len(payload) {
			var hdr [3]byte
			if _, e = io.ReadFull(res.Body, hdr[:]); e != nil {
				return e
			}
			chunk := make([]byte, int(binary.BigEndian.Uint16(hdr[:2]))+int(hdr[2]))
			if _, e = io.ReadFull(res.Body, chunk); e != nil {
				return e
			}
			got = append(got, chunk[:len(chunk)-int(hdr[2])]...)
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("payload mismatch")
		}
		return nil
	}
	for _, ib := range ins {
		for _, u := range users {
			if err = transfer(ib, u); err != nil {
				t.Fatal(err)
			}
		}
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
