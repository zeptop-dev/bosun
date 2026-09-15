package firewall

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyUFW(t *testing.T) {
	var calls []string
	m := &Manager{StateFile: filepath.Join(t.TempDir(), "fw.json"), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if call == "ufw status" {
			return []byte("Status: active\n"), nil
		}
		return nil, nil
	}}
	if err := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 443}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ufw allow 443/tcp") || !strings.Contains(joined, "ufw allow 443/udp") {
		t.Fatalf("calls: %s", joined)
	}
	if st := m.Status(); st.Kind != "ufw" || st.Opened != 2 {
		t.Fatalf("status %+v", st)
	}
	calls = nil
	if err := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 443}}); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(calls, "\n")
	if !strings.Contains(joined, "ufw delete allow 443/udp") || strings.Contains(joined, "ufw allow 443/tcp") {
		t.Fatalf("second apply: %s", joined)
	}
	// A fresh manager reads the state file and closes what it opened before.
	m2 := &Manager{StateFile: m.StateFile, Run: m.Run}
	calls = nil
	_ = m2.Apply(context.Background(), nil)
	if !strings.Contains(strings.Join(calls, "\n"), "ufw delete allow 443/tcp") {
		t.Fatalf("state not persisted: %v", calls)
	}
}

func TestNoFirewall(t *testing.T) {
	m := &Manager{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Status: inactive"), nil
	}}
	if err := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 1}}); err != nil || m.Status().Kind != "" {
		t.Fatalf("%v %+v", err, m.Status())
	}
}
