package singbox

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestStandaloneRenderNoSubscriberCredentials(t *testing.T) {
	for _, protocol := range []spec.Protocol{spec.SOCKS, spec.Shadowsocks} {
		ib := spec.Inbound{Tag: "independent", Protocol: protocol, Port: 1080, Standalone: &spec.StandaloneAuth{}}
		if protocol == spec.SOCKS {
			ib.Standalone = &spec.StandaloneAuth{Username: "operator", Password: "private-password"}
		} else {
			ib.Cipher = "2022-blake3-aes-128-gcm"
			ib.ServerKey = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}
		for _, distribution := range []string{"singbox", "singbox-extended"} {
			raw, err := render(&spec.Node{}, []spec.Inbound{ib}, users, renderOptions{Distribution: distribution, StatsListen: "127.0.0.1:9101"})
			if err != nil {
				t.Fatal(err)
			}
			cfg := decode(t, raw)
			in := cfg["inbounds"].([]any)[0].(map[string]any)
			if strings.Contains(string(raw), users[0].UUID) {
				t.Fatal("subscriber credential in standalone config")
			}
			if protocol == spec.SOCKS {
				auth := in["users"].([]any)[0].(map[string]any)
				if auth["username"] != "operator" || auth["password"] != "private-password" || len(in["users"].([]any)) != 1 {
					t.Fatal("wrong SOCKS authentication")
				}
			} else {
				if _, ok := in["users"]; ok {
					t.Fatal("single-user SS2022 rendered in multi-user mode")
				}
				if in["password"] != ib.ServerKey {
					t.Fatal("single key not used")
				}
			}
		}
	}
}

func TestStandaloneUsernameCannotImpersonateSubscriberInLogs(t *testing.T) {
	called := false
	tracker := newOnlineTracker(func(user, ip, host string, port int, network string) { called = true })
	tracker.setUsers(map[string]bool{"subscriber": true})
	tracker.setIgnoredInbounds(map[string]bool{"independent": true})
	tracker.feed("INFO [123 0ms] inbound/socks[independent]: inbound connection from 192.0.2.10:1234")
	tracker.feed("INFO [123 0ms] inbound/socks[independent]: [subscriber] inbound connection to example.com:443")
	if called || len(tracker.online()) != 0 {
		t.Fatal("standalone username polluted subscriber online state")
	}
	tracker.feed("INFO [124 0ms] inbound/vless[normal]: inbound connection from 192.0.2.10:1234")
	tracker.feed("INFO [124 0ms] inbound/vless[normal]: [subscriber] inbound connection to example.com:443")
	if !called || len(tracker.online()) != 1 {
		t.Fatal("normal listener stopped tracking users")
	}
}
