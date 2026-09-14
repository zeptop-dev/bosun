package snell

import (
	"fmt"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// render builds snell-server.conf for one inbound. Snell has a single
// shared PSK per listener, so users are not part of the config.
func render(ib spec.Inbound) ([]byte, error) {
	if ib.Protocol != spec.Snell {
		return nil, fmt.Errorf("snell: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}
	if ib.Port <= 0 {
		return nil, fmt.Errorf("snell: inbound %q: port is required", ib.Tag)
	}
	psk := strings.TrimSpace(ib.SnellPSK)
	if psk == "" {
		return nil, fmt.Errorf("snell: inbound %q: psk is required", ib.Tag)
	}
	if strings.ContainsAny(psk, "\n\r") {
		return nil, fmt.Errorf("snell: inbound %q: psk may not contain line breaks", ib.Tag)
	}
	listen := ib.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	if strings.Contains(listen, ":") && !strings.HasPrefix(listen, "[") {
		listen = "[" + listen + "]"
	}
	obfs := strings.ToLower(strings.TrimSpace(ib.SnellObfs))
	switch obfs {
	case "", "off":
		obfs = "off"
	case "http", "tls":
	default:
		return nil, fmt.Errorf("snell: inbound %q: obfs must be off, http or tls", ib.Tag)
	}
	var b strings.Builder
	b.WriteString("[snell-server]\n")
	fmt.Fprintf(&b, "listen = %s:%d\n", listen, ib.Port)
	fmt.Fprintf(&b, "psk = %s\n", psk)
	b.WriteString("ipv6 = false\n")
	fmt.Fprintf(&b, "obfs = %s\n", obfs)
	if obfs != "off" && ib.SnellObfsHost != "" {
		fmt.Fprintf(&b, "obfs-host = %s\n", ib.SnellObfsHost)
	}
	return []byte(b.String()), nil
}
