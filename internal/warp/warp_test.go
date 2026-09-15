package warp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRegisterAndResolve(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/reg":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			gotKey, _ = in["key"].(string)
			_, _ = w.Write([]byte(`{"id":"abc","token":"tok","account":{"license":"free"},"config":{"client_id":"AQID","peers":[{"public_key":"PEER","endpoint":{"host":"engage.cloudflareclient.com:2408"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8f81::1"}}}}`))
		case r.Method == "PUT" && r.URL.Path == "/reg/abc/account":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"license":"PLUS"}`))
		case r.Method == "GET" && r.URL.Path == "/reg/abc":
			_, _ = w.Write([]byte(`{"id":"abc","token":"tok","config":{"client_id":"AQID","peers":[{"public_key":"PEER2","endpoint":{"host":"engage.cloudflareclient.com:2408"}}],"interface":{"addresses":{"v4":"172.16.0.3","v6":"2606:4700:110:8f81::2"}}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	acct, err := c.Register(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if gotKey == "" || acct.PeerPublicKey != "PEER" || len(acct.Addresses) != 2 || acct.Addresses[0] != "172.16.0.2/32" || len(acct.Reserved) != 3 || acct.Reserved[2] != 3 {
		t.Fatalf("account %+v", acct)
	}
	if err := c.SetLicense(context.Background(), acct, "PLUS"); err != nil || acct.License != "PLUS" || acct.PeerPublicKey != "PEER2" {
		t.Fatalf("license: %v %+v", err, acct)
	}
	o, err := Resolve(spec.Outbound{Tag: "warp", WARP: &spec.WARP{FromNode: true}}, acct)
	if err != nil || o.WARP.PrivateKey != acct.PrivateKey || o.WARP.PeerPublicKey != "PEER2" {
		t.Fatalf("resolve: %v %+v", err, o.WARP)
	}
	if _, err := Resolve(spec.Outbound{Tag: "warp", WARP: &spec.WARP{FromNode: true}}, nil); err == nil {
		t.Fatal("resolve without account should fail")
	}
	if p := Public(acct); p.PrivateKey != "" || p.Token != "" || p.ID != "abc" {
		t.Fatalf("public: %+v", p)
	}
}
