//go:build !linux

package probe

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func probeInterfaceControl(string) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return syscall.EOPNOTSUPP }
}
func boundICMP(context.Context, spec.PingTask, net.IP) (time.Duration, error) {
	return 0, syscall.EOPNOTSUPP
}
