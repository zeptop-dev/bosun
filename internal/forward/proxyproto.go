package forward

import (
	"encoding/binary"
	"net"
)

// proxyHeaderV2 encodes a PROXY protocol v2 header (HAProxy spec) for a
// TCP connection from src to dst, so the target sees the client's real
// address instead of the relay's. Both addresses must be the same family;
// anything else yields the "LOCAL" header, which targets ignore.
func proxyHeaderV2(src, dst net.Addr) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	s, sok := src.(*net.TCPAddr)
	d, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return append(sig, 0x20, 0x00, 0x00, 0x00) // LOCAL, unspecified, length 0
	}
	if s4, d4 := s.IP.To4(), d.IP.To4(); s4 != nil && d4 != nil {
		h := append(sig, 0x21, 0x11, 0x00, 12) // PROXY, TCP over IPv4
		h = append(h, s4...)
		h = append(h, d4...)
		h = binary.BigEndian.AppendUint16(h, uint16(s.Port))
		h = binary.BigEndian.AppendUint16(h, uint16(d.Port))
		return h
	}
	if s16, d16 := s.IP.To16(), d.IP.To16(); s16 != nil && d16 != nil && s.IP.To4() == nil && d.IP.To4() == nil {
		h := append(sig, 0x21, 0x21, 0x00, 36) // PROXY, TCP over IPv6
		h = append(h, s16...)
		h = append(h, d16...)
		h = binary.BigEndian.AppendUint16(h, uint16(s.Port))
		h = binary.BigEndian.AppendUint16(h, uint16(d.Port))
		return h
	}
	return append(sig, 0x20, 0x00, 0x00, 0x00)
}
