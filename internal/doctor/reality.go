package doctor

import (
	"context"
	"net"
	"strings"

	"github.com/zeptop-dev/bosun/internal/realityscan"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (d *Deps) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if d.Lookup != nil {
		return d.Lookup(ctx, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// checkReality warns when a REALITY inbound's handshake target sits on a
// public CDN (its fallback would relay third-party traffic) or when the
// fallback rate limit is not in effect.
func checkReality(ctx context.Context, d *Deps) []Check {
	var out []Check
	for _, ib := range inbounds(d) {
		t := ib.TLS
		if t == nil || t.Mode != spec.TLSReality || t.Reality == nil {
			continue
		}
		r := t.Reality
		c := Check{ID: "reality:" + ib.Tag, Name: "REALITY " + ib.Tag, Status: OK}
		host := r.HandshakeServer
		if host == "" {
			host = t.ServerName
		}
		var notes []string
		if ips, err := d.lookup(ctx, host); err == nil {
			for _, ip := range ips {
				if cdn := realityscan.CDNByIP(ip); cdn != "" {
					c.Status = Fail
					notes = append(notes, "target "+host+" is a "+cdn+" edge ("+ip.String()+"): scanners will relay traffic through this node; pick a self-hosted site")
					break
				}
			}
		}
		if _, on := r.EffectiveFallbackLimit(); !on {
			if c.Status != Fail {
				c.Status = Warn
			}
			notes = append(notes, "fallback rate limit is off")
		} else if core := d.Assign[ib.Tag]; core != "" && core != "xray" {
			if c.Status != Fail {
				c.Status = Warn
			}
			notes = append(notes, "served by "+core+", which has no fallback rate limit; assign xray")
		}
		c.Detail = strings.Join(notes, "; ")
		out = append(out, c)
	}
	if len(out) == 0 {
		return []Check{{ID: "reality", Name: "REALITY targets", Status: Skip, Detail: "no REALITY inbounds"}}
	}
	return out
}
