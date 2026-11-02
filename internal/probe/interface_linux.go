//go:build linux

package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func probeInterfaceControl(device string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return bindErr
	}
}

// boundICMP uses a bound raw socket rather than only an outgoing packet hint.
// SO_BINDTODEVICE constrains both sending and receiving. There is no unbound
// retry after permission, route or timeout failures.
func boundICMP(ctx context.Context, t spec.PingTask, target net.IP) (time.Duration, error) {
	if err := checkProbeInterface(t); err != nil {
		return 0, err
	}
	network, source, protocol := "ip4:icmp", "0.0.0.0", 1
	var requestType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if target.To4() == nil {
		network, source, protocol = "ip6:ipv6-icmp", "::", 58
		requestType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	if t.SourceIP != "" {
		source = t.SourceIP
	}
	lc := net.ListenConfig{Control: probeInterfaceControl(t.SourceInterface)}
	conn, err := lc.ListenPacket(ctx, network, source)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return 0, err
		}
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	id := int(binary.BigEndian.Uint16(nonce[:2]))
	request := icmp.Message{Type: requestType, Body: &icmp.Echo{ID: id, Seq: 1, Data: nonce[:]}}
	wire, err := request.Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err = conn.WriteTo(wire, &net.IPAddr{IP: target}); err != nil {
		return 0, err
	}
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, err
		}
		sender, ok := addr.(*net.IPAddr)
		if !ok || !sender.IP.Equal(target) {
			continue
		}
		reply, err := icmp.ParseMessage(protocol, buf[:n])
		if err != nil || reply.Type != replyType || reply.Code != 0 {
			continue
		}
		body, ok := reply.Body.(*icmp.Echo)
		if ok && body.ID == id && body.Seq == 1 && bytes.Equal(body.Data, nonce[:]) {
			return time.Since(start), nil
		}
	}
}
