package singbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func compatibilityBinary(t *testing.T) string {
	t.Helper()
	p := os.Getenv("BOSUN_SINGBOX_TEST_BINARY")
	if p == "" {
		t.Skip("set BOSUN_SINGBOX_TEST_BINARY")
	}
	return p
}
func compatibilityCert(t *testing.T) (string, string) {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	d := t.TempDir()
	cp, kp := filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")
	if e = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0600); e != nil {
		t.Fatal(e)
	}
	return cp, kp
}
func TestRealSingboxProtocols(t *testing.T) {
	binary := compatibilityBinary(t)
	cp, kp := compatibilityCert(t)
	for _, p := range []spec.Protocol{spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks, spec.Hysteria2, spec.TUIC, spec.AnyTLS, spec.SOCKS, spec.HTTP, spec.Naive, spec.Snell} {
		t.Run(string(p), func(t *testing.T) {
			ib := spec.Inbound{Tag: "assessment", Protocol: p, Listen: "127.0.0.1", Port: 24567, Cipher: "2022-blake3-aes-128-gcm", SnellMultiUser: true}
			spec.FillInboundSecrets(&ib)
			if requiresTLS(p) {
				ib.TLS = &spec.TLS{Mode: spec.TLSStandard, ServerName: "example.com", CertPath: cp, KeyPath: kp}
			}
			raw, e := render(&spec.Node{}, []spec.Inbound{ib}, users, renderOptions{StatsListen: "127.0.0.1:24568"})
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			out, e := exec.Command(binary, "check", "-c", path).CombinedOutput()
			if e != nil {
				t.Fatalf("%v: %s", e, out)
			}
		})
	}
}
func TestRealSingboxAccountingAndReload(t *testing.T) {
	binary := compatibilityBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
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
	ins := []spec.Inbound{{Tag: "a", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: port()}, {Tag: "b", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: port()}}
	stats := net.JoinHostPort("127.0.0.1", strconv.Itoa(port()))
	for _, l := range leases {
		l.Close()
	}
	c, e := New(Options{Binary: binary, WorkDir: t.TempDir(), StatsListen: stats}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Stop(context.Background())
	node := &spec.Node{AllowPrivateDest: true, Inbounds: ins}
	b, e := c.Render(node, ins, users)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(ctx, b); e != nil {
		t.Fatal(e)
	}
	transfer := func(ib spec.Inbound, u spec.User) error {
		var conn net.Conn
		var err error
		for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
			conn, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port)), time.Second)
			if err == nil {
				break
			}
		}
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		uuid, _ := hex.DecodeString(strings.ReplaceAll(u.UUID, "-", ""))
		tp := target.Addr().(*net.TCPAddr).Port
		header := append([]byte{0}, uuid...)
		header = append(header, 0, 1, byte(tp>>8), byte(tp), 1, 127, 0, 0, 1)
		payload := bytes.Repeat([]byte("assessment"), 2048)
		if _, err = conn.Write(append(header, payload...)); err != nil {
			return err
		}
		response := make([]byte, 2)
		if _, err = io.ReadFull(conn, response); err != nil {
			return err
		}
		if response[1] > 0 {
			if _, err = io.CopyN(io.Discard, conn, int64(response[1])); err != nil {
				return err
			}
		}
		got := make([]byte, len(payload))
		_, err = io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, payload) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	for _, ib := range ins {
		for _, u := range users {
			if e = transfer(ib, u); e != nil {
				t.Fatal(e)
			}
		}
	}
	// A candidate config rejected by the new parser must not affect the
	// running process or its accepted configuration.
	badNode := *node
	badNode.Outbounds = []spec.Outbound{{Tag: "duplicate", Balancer: &spec.Balancer{Members: []string{"direct", "direct"}}}}
	badBundle, err := c.Render(&badNode, ins, users)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Check(ctx, badBundle); err == nil {
		t.Fatal("duplicate group passed candidate preflight")
	}
	if !c.Running() {
		t.Fatal("candidate preflight stopped active core")
	}
	if err = transfer(ins[0], users[0]); err != nil {
		t.Fatalf("active config changed by preflight: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	us, e := c.Stats(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, ib := range ins {
		for _, u := range users {
			v := us[spec.InboundUser(u.Name, ib.Tag)]
			if v.Up < 20480 || v.Down < 20480 {
				t.Fatalf("missing scoped counter %s: %+v", ib.Tag, us)
			}
		}
	}
	is, e := c.InboundStats(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, ib := range ins {
		if is[ib.Tag].Up < 40960 || is[ib.Tag].Down < 40960 {
			t.Fatalf("user reset consumed inbound counters: %+v", is)
		}
	}
	zero, e := c.Stats(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range zero {
		if v.Up != 0 || v.Down != 0 {
			t.Fatalf("counter reset failed: %+v", zero)
		}
	}
	b, e = c.Render(node, ins, users[:1])
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Apply(ctx, b); e != nil {
		t.Fatal(e)
	}
	if e = transfer(ins[0], users[0]); e != nil {
		t.Fatalf("retained user after restart: %v", e)
	}
	if e = transfer(ins[0], users[1]); e == nil {
		t.Fatal("revoked user still accepted")
	}
}
