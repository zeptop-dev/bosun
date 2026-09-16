package forward

import (
	"bytes"
	"net"
	"testing"
)

func TestProxyHeaderV2(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 51234}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}
	h := proxyHeaderV2(src, dst)
	if len(h) != 28 || !bytes.HasPrefix(h, []byte("\r\n\r\n\x00\r\nQUIT\n")) || h[12] != 0x21 || h[13] != 0x11 {
		t.Fatalf("v4 header: % x", h)
	}
	if !bytes.Equal(h[16:20], []byte{203, 0, 113, 9}) || !bytes.Equal(h[20:24], []byte{198, 51, 100, 20}) || h[24] != 0xC8 || h[25] != 0x22 || h[26] != 0x01 || h[27] != 0xBB {
		t.Fatalf("v4 addresses/ports: % x", h[16:])
	}
	h6 := proxyHeaderV2(&net.TCPAddr{IP: net.ParseIP("2001:db8::9"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 2})
	if len(h6) != 52 || h6[13] != 0x21 {
		t.Fatalf("v6 header: % x", h6)
	}
	mixed := proxyHeaderV2(src, &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 2})
	if len(mixed) != 16 || mixed[12] != 0x20 {
		t.Fatalf("mixed families must give a LOCAL header: % x", mixed)
	}
}
