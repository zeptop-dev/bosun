package runas

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The cores run as an unprivileged account and have to traverse the data
// directory to reach their binary and their work dir. The OpenRC service
// file once set it to 0750, which made every core on Alpine fail to start
// with "fork/exec ...: permission denied" while systemd hosts were fine,
// because the installer's plain mkdir leaves 0755.
func TestOpenRCLeavesTheDataDirTraversable(t *testing.T) {
	b, err := os.ReadFile("../../deploy/bosun.initd")
	if err != nil {
		t.Skip("service file not present:", err)
	}
	m := regexp.MustCompile(`checkpath -d -m (\d+) /var/lib/bosun`).FindSubmatch(b)
	if m == nil {
		t.Fatal("the service file no longer sets a mode on the data dir")
	}
	mode, err := strconv.ParseInt(string(m[1]), 8, 32)
	if err != nil {
		t.Fatalf("mode %q: %v", m[1], err)
	}
	if mode&0o1 == 0 {
		t.Fatalf("mode %04o does not let the core account enter the data dir", mode)
	}
}
