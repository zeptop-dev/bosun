package ui

import (
	"context"
	"net/http"
	"time"

	"github.com/zeptop-dev/bosun/internal/realityscan"
)

// realityScan probes REALITY target candidates from this node: the
// operator's list, or the built-in pool when it is empty.
func (s *Server) realityScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hosts []string `json:"hosts"`
		Port  int      `json:"port"`
	}
	_ = decode(r, &in)
	if len(in.Hosts) > 32 {
		in.Hosts = in.Hosts[:32]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	ok(w, realityscan.Scan(ctx, in.Hosts, realityscan.Options{Port: in.Port}))
}
