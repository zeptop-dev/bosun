package ui

import (
	"context"
	"net"
	"time"

	"github.com/zeptop-dev/bosun/internal/dns"
	"github.com/zeptop-dev/bosun/internal/komari"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// dnsSync creates or updates A/AAAA records for names when a Cloudflare
// token is configured: the panel domain, the decoy site and TLS inbound
// names all have to point at this node anyway. Nil when there is nothing
// to do; errors are reported per record, never fatal.
func (s *Server) dnsSync(ctx context.Context, names ...string) []dns.Result {
	st := s.d.Store.Settings()
	if st.CloudflareToken == "" {
		return nil
	}
	var todo []string
	for _, n := range names {
		if n != "" && net.ParseIP(n) == nil {
			todo = append(todo, n)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	ip4, ip6 := "", ""
	if ip := net.ParseIP(st.PublicHost); ip != nil {
		if ip.To4() != nil {
			ip4 = ip.String()
		} else {
			ip6 = ip.String()
		}
	} else {
		ip4, ip6 = komari.DetectPublicIPs(ctx)
	}
	if ip4 == "" && ip6 == "" {
		return []dns.Result{{Name: todo[0], Action: "skipped", Error: "cannot determine this node's public address"}}
	}
	res := (&dns.Cloudflare{Token: st.CloudflareToken}).EnsureAll(ctx, todo, ip4, ip6)
	for _, r := range res {
		if r.Error != "" {
			s.d.Log.Warn("dns record", "name", r.Name, "err", r.Error)
		} else if r.Action != "unchanged" {
			s.d.Log.Info("dns record "+r.Action, "name", r.Name, "ip", r.IP)
		}
	}
	return res
}

// tlsNames lists the domains an inbound needs to resolve here.
func tlsNames(ib spec.Inbound) []string {
	if ib.TLS != nil && ib.TLS.Mode == spec.TLSStandard && ib.TLS.ServerName != "" {
		return []string{ib.TLS.ServerName}
	}
	return nil
}
