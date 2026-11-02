package probe

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

var errProbeInterface = errors.New("probe interface unavailable")

func checkProbeInterface(t spec.PingTask) error {
	if runtime.GOOS != "linux" {
		return syscall.EOPNOTSUPP
	}
	device, err := net.InterfaceByName(t.SourceInterface)
	if err != nil || device.Flags&net.FlagUp == 0 {
		return errProbeInterface
	}
	if t.SourceIP == "" {
		return nil
	}
	addrs, err := device.Addrs()
	if err != nil {
		return fmt.Errorf("%w: addresses unavailable", errProbeInterface)
	}
	for _, addr := range addrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.Equal(net.ParseIP(t.SourceIP)) {
			return nil
		}
	}
	return fmt.Errorf("%w: source address is not on selected device", errProbeInterface)
}
