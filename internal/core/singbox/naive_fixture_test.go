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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/http2"
)

func naiveTestTransfer(ctx context.Context, pool *x509.CertPool, serverAddress, target string, u spec.User, payload []byte) error {
	callCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
	defer tr.CloseIdleConnections()
	rd, wr := io.Pipe()
	defer rd.Close()
	defer wr.Close()
	req, _ := http.NewRequestWithContext(callCtx, "CONNECT", "https://"+serverAddress, rd)
	req.Host = target
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
	writeDone := make(chan error, 1)
	go func() {
		frame := make([]byte, 3+len(payload))
		binary.BigEndian.PutUint16(frame, uint16(len(payload)))
		copy(frame[3:], payload)
		_, e := wr.Write(frame)
		if e != nil {
			wr.CloseWithError(e)
		}
		writeDone <- e
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
	// End the request cleanly, then consume the server's END_STREAM. Closing
	// Response.Body or cancelling first sends RST_STREAM and can interrupt a
	// final proxy WriteBuffer after the client has already received its bytes.
	select {
	case err := <-writeDone:
		if err != nil {
			return err
		}
	case <-callCtx.Done():
		return callCtx.Err()
	}
	if err := wr.Close(); err != nil {
		return err
	}
	_, err := io.Copy(io.Discard, res.Body)
	return err
}

// A delivered echo is not a completed HTTP/2 CONNECT stream. The server waits
// for request EOF before finishing its response, making premature cancellation
// observable without relying on the proxy core's accounting scheduler.
func TestNaiveFixtureCompletesStream(t *testing.T) {
	cp, kp := compatibilityCert(t)
	certificate, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		var header [3]byte
		if _, err := io.ReadFull(r.Body, header[:]); err != nil {
			requestDone <- err
			return
		}
		frame := make([]byte, int(binary.BigEndian.Uint16(header[:2]))+int(header[2]))
		if _, err := io.ReadFull(r.Body, frame); err != nil {
			requestDone <- err
			return
		}
		if _, err := w.Write(append(header[:], frame...)); err != nil {
			requestDone <- err
			return
		}
		w.(http.Flusher).Flush()
		_, err := io.Copy(io.Discard, r.Body)
		requestDone <- err
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = naiveTestTransfer(ctx, pool, strings.TrimPrefix(server.URL, "https://"), "example.com:443", spec.User{Name: "fixture", Password: "fixture-password"}, []byte("completed transfer")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatalf("client cancelled before graceful request EOF: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("request did not finish")
	}
}
