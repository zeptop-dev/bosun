package hysteria

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// authServer answers hysteria's HTTP auth callbacks. Hysteria POSTs
// {"addr","auth","tx"} for every new client and expects {"ok","id"}; the id
// becomes the key in its traffic stats, so we answer with the user name.
type authServer struct {
	log *slog.Logger
	srv *http.Server

	mu    sync.RWMutex
	users map[string]spec.User // auth string -> user
}

type authRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   uint64 `json:"tx"`
}

func newAuthServer(listen string, log *slog.Logger) (*authServer, error) {
	a := &authServer{log: log, users: map[string]spec.User{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", a.handle)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	a.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = a.srv.Serve(ln) }()
	return a, nil
}

func (a *authServer) setUsers(users map[string]spec.User) {
	a.mu.Lock()
	a.users = users
	a.mu.Unlock()
}

func (a *authServer) handle(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a.mu.RLock()
	u, ok := a.users[req.Auth]
	a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		a.log.Debug("auth rejected", "addr", req.Addr)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": u.Name})
}

func (a *authServer) close(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
