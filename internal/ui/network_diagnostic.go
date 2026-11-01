package ui

import (
	"net/http"
	"path/filepath"

	"github.com/zeptop-dev/bosun/internal/netdiag"
	"github.com/zeptop-dev/bosun/pkg/agentdownload"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (s *Server) networkDiagnostic(w http.ResponseWriter, r *http.Request) {
	var in spec.DiagnosticRequest
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := in.Validate(); err != nil {
		fail(w, 400, err)
		return
	}
	// The normal request log records the route and outcome, never URL query
	// strings or diagnostic output. The authenticated local admin initiated it.
	ctx := r.Context()
	if s.d.Install != nil && s.d.Install.Downloads != nil {
		ctx = agentdownload.WithClient(ctx, s.d.Install.Downloads)
	}
	ok(w, netdiag.Default.Run(ctx, in, filepath.Dir(s.d.Store.Path())))
}
