//go:build !linux

package forward

import (
	"errors"
	"syscall"
)

func serviceSocketControl(_, _ string, _ syscall.RawConn) error {
	return errors.New("service control relay sockets require Linux")
}
