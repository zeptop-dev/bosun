package dns

import (
	"context"
	"os"
	"testing"
	"time"
)

// This read-only opt-in test is cross-compiled and run on the target host.
// Never print the host's public address in test artifacts.
func TestMainlandIPv4SourcesLive(t *testing.T) {
	if os.Getenv("BOSUN_PUBLIC_IP_LIVE") != "1" {
		t.Skip("explicit live-network opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	start := time.Now()
	values := observeFamilySources(ctx, client, []string{ipipSource, mainlandTextSource}, false)
	for i, v := range values {
		if v == "" {
			t.Fatalf("source %d did not return a valid HTTPS IPv4 observation", i)
		}
	}
	if addressConsensus(values) == "" {
		t.Fatal("independent mainland observations disagree")
	}
	t.Logf("two HTTPS IPv4 sources agree; elapsed=%s", time.Since(start).Round(time.Millisecond))
}
