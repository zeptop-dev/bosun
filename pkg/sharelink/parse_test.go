package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestParseURI(t *testing.T) {
	l, err := ParseURI("vless://11111111-1111-1111-1111-111111111111@vip.test:443?security=reality&pbk=PUB&sid=0123&sni=www.apple.com&type=tcp&flow=xtls-rprx-vision#JP")
	if err != nil || l.Name != "JP" || l.Host != "vip.test" || l.Port != 443 || l.Inbound.Protocol != spec.VLESS || l.Inbound.Flow != "xtls-rprx-vision" {
		t.Fatalf("vless: %+v %v", l, err)
	}
	if l.Inbound.TLS == nil || l.Inbound.TLS.Mode != spec.TLSReality || l.Inbound.TLS.Reality.PublicKey != "PUB" || l.Inbound.TLS.Reality.ShortIDs[0] != "0123" {
		t.Fatalf("reality: %+v", l.Inbound.TLS)
	}
	tr, err := ParseURI("trojan://pw@t.test:443?type=ws&path=%2Ftr&host=t.test&sni=t.test#a")
	if err != nil || tr.Password != "pw" || tr.Inbound.Transport == nil || tr.Inbound.Transport.Type != "ws" || tr.Inbound.Transport.Path != "/tr" || tr.Inbound.TLS.ServerName != "t.test" {
		t.Fatalf("trojan: %+v %v", tr, err)
	}
	hy, err := ParseURI("hysteria2://pw@h.test:8443?sni=h.test&obfs=salamander&obfs-password=x#h")
	if err != nil || hy.Inbound.Protocol != spec.Hysteria2 || hy.Inbound.Obfs != "salamander" || hy.Inbound.ObfsPassword != "x" {
		t.Fatalf("hy2: %+v %v", hy, err)
	}
	// Legacy fully-base64 ss link and a plain-userinfo SIP002 link.
	ss1, err := ParseURI("ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@192.0.2.10:8388")) + "#legacy")
	if err != nil || ss1.Inbound.Cipher != "aes-256-gcm" || ss1.Password != "secret" || ss1.Host != "192.0.2.10" || ss1.Name != "legacy" {
		t.Fatalf("legacy ss: %+v %v", ss1, err)
	}
	ss2, err := ParseURI("ss://chacha20-ietf-poly1305:p%40ss@host.test:443?plugin=obfs#plain")
	if err != nil || ss2.Password != "p@ss" || ss2.Port != 443 {
		t.Fatalf("sip002 ss: %+v %v", ss2, err)
	}
	// vmess with numeric port and h2.
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"vm.test","port":443,"id":"uuid-1","net":"h2","path":"/h","host":"vm.test","tls":"tls"}`))
	l, err = ParseURI("vmess://" + vm)
	if err != nil || l.Port != 443 || l.Inbound.Transport.Type != "http" || l.Inbound.TLS == nil {
		t.Fatalf("vmess: %+v %v", l, err)
	}
	// socks with credentials becomes a Remote with username.
	sk, err := ParseURI("socks://user:pw@10.10.0.2:1080#exit")
	if err != nil || sk.Remote().Username != "user" || sk.Remote().Password != "pw" || sk.Remote().UUID != "" {
		t.Fatalf("socks: %+v %v", sk, err)
	}
	if _, err := ParseURI("ftp://x"); err == nil {
		t.Fatal("unsupported scheme accepted")
	}
	// Subscription body: base64 list with one bad line.
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{"trojan://pw@t.test:443?sni=t.test#a", "garbage://", "ss://bad"}, "\n")))
	lines, skipped := ParseList(body)
	if len(lines) != 1 || skipped != 2 || lines[0].Name != "a" {
		t.Fatalf("list: %d skipped %d", len(lines), skipped)
	}
}
