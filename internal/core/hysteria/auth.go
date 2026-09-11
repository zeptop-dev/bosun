package hysteria

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// authServer answers hysteria's HTTP auth callbacks. Hysteria POSTs
// {"addr","auth","tx"} for every new client and expects {"ok","id"}; the id
// becomes the key in its traffic stats, so we answer with the user name.
type authServer struct {
	log *slog.Logger
	srv *http.Server

	mu    sync.RWMutex
	users map[string]spec.User // auth string -> user
	// seen records client IPs per user name at auth time; hysteria's own
	// /online endpoint only counts connections, so this is the IP source.
	seen map[string]map[string]time.Time
}

// onlineWindow is how long an authenticated IP counts as online.
const onlineWindow = 5 * time.Minute

type authRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   uint64 `json:"tx"`
}

func newAuthServer(listen string, log *slog.Logger) (*authServer, error) {
	a := &authServer{log: log, users: map[string]spec.User{}, seen: map[string]map[string]time.Time{}}
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
	a.record(u.Name, req.Addr)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": u.Name})
}

func (a *authServer) record(user, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return
	}
	a.mu.Lock()
	m := a.seen[user]
	if m == nil {
		m = map[string]time.Time{}
		a.seen[user] = m
	}
	m[host] = time.Now()
	a.mu.Unlock()
}

// online returns IPs seen within onlineWindow, dropping stale ones.
func (a *authServer) online() map[string][]string {
	cutoff := time.Now().Add(-onlineWindow)
	out := map[string][]string{}
	a.mu.Lock()
	defer a.mu.Unlock()
	for user, m := range a.seen {
		for ip, at := range m {
			if at.Before(cutoff) {
				delete(m, ip)
				continue
			}
			out[user] = append(out[user], ip)
		}
		if len(m) == 0 {
			delete(a.seen, user)
		}
	}
	return out
}

func (a *authServer) close(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
