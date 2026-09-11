package xboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

const configJSON = `{
  "protocol":"vless","listen_ip":"0.0.0.0","server_port":443,"network":"tcp","networkSettings":null,
  "tls":2,"flow":"xtls-rprx-vision",
  "tls_settings":{"server_name":"www.apple.com","server_port":"443","public_key":"pub","private_key":"priv","short_id":"0123","allow_insecure":false},
  "multiplex":{"enabled":false},
  "custom_outbounds":[{"tag":"landing","protocol":"socks","settings":{"server":"1.2.3.4","server_port":1080},"proxy_tag":""}],
  "base_config":{"push_interval":30,"pull_interval":45}
}`

const usersJSON = `{"users":[{"id":7,"uuid":"aaaaaaaa-0000-0000-0000-000000000000","speed_limit":100,"device_limit":3}]}`

func newServer(t *testing.T, pushed *map[string][2]int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("token") != "tok" || q.Get("node_id") != "5" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case pathConfig:
			if r.Header.Get("If-None-Match") == `"cfg-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"cfg-1"`)
			io.WriteString(w, configJSON)
		case pathUser:
			w.Header().Set("ETag", `"u-1"`)
			io.WriteString(w, usersJSON)
		case pathPush:
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, pushed)
			io.WriteString(w, `{"data":true}`)
		case pathStatus:
			io.WriteString(w, `{"data":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestClient(t *testing.T) {
	pushed := map[string][2]int64{}
	srv := newServer(t, &pushed)
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "tok", NodeID: 5}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	node, changed, err := c.Node(ctx)
	if err != nil || !changed {
		t.Fatalf("Node: changed=%v err=%v", changed, err)
	}
	ib := node.Inbounds[0]
	if ib.Protocol != spec.VLESS || ib.Port != 443 || ib.Listen != "::" || ib.Flow != "xtls-rprx-vision" {
		t.Fatalf("inbound: %+v", ib)
	}
	if ib.TLS == nil || ib.TLS.Mode != spec.TLSReality || ib.TLS.Reality.PrivateKey != "priv" || ib.TLS.Reality.HandshakePort != 443 || ib.TLS.Reality.ShortIDs[0] != "0123" {
		t.Fatalf("tls: %+v", ib.TLS)
	}
	if len(node.Outbounds) != 1 || node.Outbounds[0].Tag != "landing" {
		t.Fatalf("outbounds: %+v", node.Outbounds)
	}
	if iv := c.Intervals(); iv.Push.Seconds() != 30 || iv.Pull.Seconds() != 45 {
		t.Fatalf("intervals: %+v", iv)
	}

	// Second call hits the ETag and reports no change.
	node2, changed, err := c.Node(ctx)
	if err != nil || changed || node2 != nil {
		t.Fatalf("Node (304): node=%v changed=%v err=%v", node2, changed, err)
	}

	users, changed, err := c.Users(ctx)
	if err != nil || !changed || len(users) != 1 {
		t.Fatalf("Users: %v %v %v", users, changed, err)
	}
	if users[0].ID != 7 || users[0].Name != users[0].UUID || users[0].SpeedLimitMbps != 100 || users[0].DeviceLimit != 3 {
		t.Fatalf("user: %+v", users[0])
	}

	if err := c.PushTraffic(ctx, []spec.UserTraffic{{UserID: 7, Up: 100, Down: 200}}); err != nil {
		t.Fatal(err)
	}
	if pushed["7"] != [2]int64{100, 200} {
		t.Fatalf("pushed: %v", pushed)
	}
	if err := c.PushStatus(ctx, spec.SystemStatus{CPUPercent: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestMapHysteriaV1Rejected(t *testing.T) {
	_, err := mapNode(1, &nodeConfig{Protocol: "hysteria", Version: 1})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMapTransportWS(t *testing.T) {
	raw := &nodeConfig{Protocol: "vmess", ServerPort: 80, Network: "ws",
		NetworkSettings: map[string]any{"path": "/ws", "headers": map[string]any{"Host": "cdn.example.com"}}}
	n, err := mapNode(2, raw)
	if err != nil {
		t.Fatal(err)
	}
	tr := n.Inbounds[0].Transport
	if tr == nil || tr.Type != "ws" || tr.Path != "/ws" || tr.Host != "cdn.example.com" {
		t.Fatalf("transport: %+v", tr)
	}
}
