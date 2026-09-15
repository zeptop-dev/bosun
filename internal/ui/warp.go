package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zeptop-dev/bosun/internal/warp"
)

// WARP account management for the standalone panel. Registration talks to
// Cloudflare from this node; the keys never leave the state file.

func (s *Server) getWARP(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"account": warp.Public(s.d.Store.WARP())})
}

func (s *Server) registerWARP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		License string `json:"license"`
	}
	_ = decode(r, &in)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	acct, err := (&warp.Client{}).Register(ctx, in.License)
	if acct == nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	if serr := s.d.Store.SetWARP(acct); serr != nil {
		fail(w, http.StatusInternalServerError, serr)
		return
	}
	resp := map[string]any{"account": warp.Public(acct)}
	if err != nil {
		resp["warning"] = err.Error()
	}
	ok(w, resp)
}

func (s *Server) licenseWARP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		License string `json:"license"`
	}
	_ = decode(r, &in)
	acct := s.d.Store.WARP()
	if acct == nil {
		fail(w, http.StatusBadRequest, errors.New("register WARP first"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := (&warp.Client{}).SetLicense(ctx, acct, in.License); err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	if err := s.d.Store.SetWARP(acct); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	ok(w, map[string]any{"account": warp.Public(acct)})
}

func (s *Server) deleteWARP(w http.ResponseWriter, r *http.Request) {
	storeErr(w, s.d.Store.SetWARP(nil))
}
