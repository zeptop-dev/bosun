//go:build linux

package forward

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/sys/unix"
	"syscall"
)

func serviceSocketControl(_, _ string, conn syscall.RawConn) error {
	var sockErr error
	err := conn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, spec.ServiceControlSocketMark)
	})
	if err != nil {
		return err
	}
	return sockErr
}
