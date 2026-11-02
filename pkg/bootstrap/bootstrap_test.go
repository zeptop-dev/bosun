package bootstrap

import (
	"bytes"
	"testing"

	"github.com/zeptop-dev/bosun/deploy"
)

func TestOpenWrtServiceDistribution(t *testing.T) {
	raw, ok := File("bosun.procd")
	if !ok || !bytes.Equal(raw, []byte(deploy.Procd)) {
		t.Fatal("missing embedded OpenWrt service")
	}
	for _, name := range []string{"../bosun.procd", "deploy/bosun.procd", "/etc/init.d/bosun"} {
		if _, ok := File(name); ok {
			t.Fatalf("accepted path %q", name)
		}
	}
}
