// Package ui is bosun's built-in web panel: a JSON API over the local store
// plus the embedded single-page app. In local mode it edits inbounds, users
// and forwards; in managed mode it is read-only diagnostics with a detach
// button.
package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/logring"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/web"
)

const (
	sessionCookie = "bosun_session"
	sessionTTL    = 7 * 24 * time.Hour
)

// Deps is what the server needs from the rest of bosun.
type Deps struct {
	Store   *local.Store
	Version string
	Log     *slog.Logger
	Logs    *logring.Ring          // may be nil
	Install *coreinstall.Installer // may be nil
	// Fixed is set when the config file pins a headless driver: the UI then
	// shows diagnostics only and cannot adopt or detach.
	Fixed string
	// Adopt pairs with a Captain panel and flips the store to managed mode.
	Adopt func(ctx context.Context, url, pairCode string) error
	// Detach flips back to local mode; keep copies the last managed state.
	Detach func(ctx context.Context, keep bool) error
	// ManagedState returns the last state pushed by the panel, if any.
	ManagedState func() *agentproto.State
	Secure       bool // cookies get the Secure flag
}

// Server is the panel HTTP handler.
type Server struct {
	d     Deps
	mux   *http.ServeMux
	start time.Time

	mu       sync.Mutex
	agent    *agent.Agent
	sessions map[string]time.Time
	failed   map[string]failure
}

type failure struct {
	count int
	last  time.Time
}

// New builds the handler.
func New(d Deps) *Server {
	s := &Server{d: d, mux: http.NewServeMux(), start: time.Now(), sessions: map[string]time.Time{}, failed: map[string]failure{}}
	s.routes()
	return s
}

// SetAgent points the UI at the currently running agent (it changes when
// the mode flips).
func (s *Server) SetAgent(a *agent.Agent) {
	s.mu.Lock()
	s.agent = a
	s.mu.Unlock()
}

func (s *Server) currentAgent() *agent.Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.agent
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("GET /sub/{token}", s.subscription)

	auth := s.requireAuth
	m.HandleFunc("GET /api/me", auth(s.me))
	m.HandleFunc("GET /api/status", auth(s.status))
	m.HandleFunc("GET /api/logs", auth(s.logs))
	m.HandleFunc("GET /api/cores", auth(s.cores))

	m.HandleFunc("GET /api/inbounds", auth(s.listInbounds))
	m.HandleFunc("POST /api/inbounds", auth(s.local(s.createInbound)))
	m.HandleFunc("PUT /api/inbounds/{tag}", auth(s.local(s.updateInbound)))
	m.HandleFunc("DELETE /api/inbounds/{tag}", auth(s.local(s.deleteInbound)))

	m.HandleFunc("GET /api/users", auth(s.listUsers))
	m.HandleFunc("POST /api/users", auth(s.local(s.createUser)))
	m.HandleFunc("PUT /api/users/{id}", auth(s.local(s.updateUser)))
	m.HandleFunc("DELETE /api/users/{id}", auth(s.local(s.deleteUser)))
	m.HandleFunc("POST /api/users/{id}/reset", auth(s.local(s.resetUser)))
	m.HandleFunc("POST /api/users/{id}/rotate", auth(s.local(s.rotateUser)))
	m.HandleFunc("GET /api/users/{id}/links", auth(s.userLinks))

	m.HandleFunc("GET /api/forwards", auth(s.listForwards))
	m.HandleFunc("POST /api/forwards", auth(s.local(s.createForward)))
	m.HandleFunc("PUT /api/forwards/{tag}", auth(s.local(s.updateForward)))
	m.HandleFunc("DELETE /api/forwards/{tag}", auth(s.local(s.deleteForward)))

	m.HandleFunc("GET /api/settings", auth(s.getSettings))
	m.HandleFunc("PUT /api/settings", auth(s.putSettings))
	m.HandleFunc("PUT /api/admin", auth(s.putAdmin))
	m.HandleFunc("POST /api/keys/{kind}", auth(s.keys))

	m.HandleFunc("POST /api/mode/adopt", auth(s.adopt))
	m.HandleFunc("POST /api/mode/detach", auth(s.detach))

	m.Handle("/", web.UI())
}

// ---- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, v any) { writeJSON(w, http.StatusOK, v) }

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func storeErr(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		ok(w, map[string]bool{"ok": true})
	case errors.Is(err, local.ErrNotFound):
		fail(w, http.StatusNotFound, err)
	default:
		fail(w, http.StatusBadRequest, err)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, errors.New("not signed in"))
			return
		}
		s.mu.Lock()
		exp, found := s.sessions[c.Value]
		if found && time.Now().After(exp) {
			delete(s.sessions, c.Value)
			found = false
		}
		s.mu.Unlock()
		if !found {
			fail(w, http.StatusUnauthorized, errors.New("session expired"))
			return
		}
		next(w, r)
	}
}

// local rejects mutations while a panel owns the node.
func (s *Server) local(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mode, _, _ := s.d.Store.Mode(); mode != local.ModeLocal || s.d.Fixed != "" {
			fail(w, http.StatusConflict, errors.New("node is managed by a panel; detach first"))
			return
		}
		next(w, r)
	}
}

// ---- auth ------------------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	f := s.failed[ip]
	s.mu.Unlock()
	if f.count >= 5 && time.Since(f.last) < time.Minute {
		fail(w, http.StatusTooManyRequests, errors.New("too many attempts; wait a minute"))
		return
	}
	if !s.d.Store.Login(in.Username, in.Password) {
		s.mu.Lock()
		s.failed[ip] = failure{count: f.count + 1, last: time.Now()}
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		fail(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	tok := authutil.Token(32)
	s.mu.Lock()
	delete(s.failed, ip)
	s.sessions[tok] = time.Now().Add(sessionTTL)
	for k, exp := range s.sessions {
		if time.Now().After(exp) {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.d.Secure, MaxAge: int(sessionTTL.Seconds())})
	ok(w, map[string]any{"username": in.Username, "version": s.d.Version})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	ok(w, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	mode, _, _ := s.d.Store.Mode()
	ok(w, map[string]any{"username": s.d.Store.Username(), "version": s.d.Version, "mode": mode, "fixed": s.d.Fixed})
}

// ---- status ----------------------------------------------------------------

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	mode, managed, snap := s.d.Store.Mode()
	rt := s.d.Store.Runtime()
	var ag any
	var forwards []agentproto.ForwardStatus
	if a := s.currentAgent(); a != nil {
		st := a.Status()
		ag = st
		for _, f := range st.Forwards {
			forwards = append(forwards, agentproto.ForwardStatus{Tag: f.Tag, Up: f.Up, RTTMillis: f.RTT.Milliseconds(), LastError: f.LastError,
				ActiveConn: f.ActiveConn, TotalConn: f.TotalConn, BytesIn: f.BytesIn, BytesOut: f.BytesOut})
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	host := sysinfo.Snapshot(ctx)
	if forwards == nil {
		forwards = []agentproto.ForwardStatus{}
	}
	users := s.d.Store.ListUsers()
	var totalUp, totalDown int64
	online := 0
	for _, u := range users {
		totalUp += u.Up
		totalDown += u.Down
		if len(rt.Online[u.UUID]) > 0 {
			online++
		}
	}
	ok(w, map[string]any{
		"version": s.d.Version, "uptime_seconds": int(time.Since(s.start).Seconds()),
		"mode": mode, "fixed": s.d.Fixed, "managed": managed, "has_snapshot": snap != nil,
		"agent": ag, "host": host, "forwards": forwards,
		"online_users": online, "users": len(users), "inbounds": len(s.d.Store.Inbounds()),
		"total_up": totalUp, "total_down": totalDown, "history": rt.History, "last_report": rt.LastReport,
	})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 200
	}
	if s.d.Logs == nil {
		ok(w, []logring.Entry{})
		return
	}
	ok(w, s.d.Logs.Last(n))
}

func (s *Server) cores(w http.ResponseWriter, r *http.Request) {
	type release struct {
		Core, Version, Status, Note string
		Installed                   bool
	}
	var out []release
	for _, name := range coreinstall.Cores() {
		for _, rel := range coreinstall.Releases(name) {
			installed := false
			if s.d.Install != nil {
				installed = s.d.Install.Installed(name, rel.Version)
			}
			out = append(out, release{Core: name, Version: rel.Version, Status: string(rel.Status), Note: rel.Note, Installed: installed})
		}
	}
	ok(w, out)
}

// ---- inbounds --------------------------------------------------------------

func (s *Server) listInbounds(w http.ResponseWriter, r *http.Request) {
	st := s.currentAgent()
	assign := map[string]string{}
	if st != nil {
		assign = st.Status().Assign
	}
	type row struct {
		local.Inbound
		AssignedCore string `json:"assigned_core"`
	}
	out := []row{}
	for _, ib := range s.d.Store.Inbounds() {
		out = append(out, row{Inbound: ib, AssignedCore: assign[ib.Tag]})
	}
	ok(w, out)
}

func (s *Server) createInbound(w http.ResponseWriter, r *http.Request) {
	var ib local.Inbound
	if err := decode(r, &ib); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.PutInbound(ib, ""))
}

func (s *Server) updateInbound(w http.ResponseWriter, r *http.Request) {
	var ib local.Inbound
	if err := decode(r, &ib); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.PutInbound(ib, r.PathValue("tag")))
}

func (s *Server) deleteInbound(w http.ResponseWriter, r *http.Request) {
	storeErr(w, s.d.Store.DeleteInbound(r.PathValue("tag")))
}

// ---- users -----------------------------------------------------------------

type userRow struct {
	local.User
	Online []string `json:"online"`
	Usable bool     `json:"usable"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	rt := s.d.Store.Runtime()
	now := time.Now()
	out := []userRow{}
	for _, u := range s.d.Store.ListUsers() {
		ips := rt.Online[u.UUID]
		if ips == nil {
			ips = []string{}
		}
		out = append(out, userRow{User: u, Online: ips, Usable: u.Usable(now)})
	}
	ok(w, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var u local.User
	if err := decode(r, &u); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	created, err := s.d.Store.CreateUser(u)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ok(w, created)
}

func userID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	var u local.User
	if err := decode(r, &u); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	u.ID = id
	storeErr(w, s.d.Store.UpdateUser(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.DeleteUser(id))
}

func (s *Server) resetUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.ResetTraffic(id))
}

func (s *Server) rotateUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	tok, err := s.d.Store.RotateSubToken(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	ok(w, map[string]string{"sub_token": tok})
}

// requestHost is the address the UI was reached on, used for links when no
// public host is configured.
func requestHost(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.Trim(h, "[]")
}

func (s *Server) userLinks(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	u, found := s.d.Store.User(id)
	if !found {
		fail(w, http.StatusNotFound, local.ErrNotFound)
		return
	}
	scheme := "http"
	if r.TLS != nil || s.d.Secure {
		scheme = "https"
	}
	ok(w, map[string]any{
		"links":   linksFor(u, s.d.Store.Inbounds(), s.d.Store.Settings(), requestHost(r)),
		"sub_url": fmt.Sprintf("%s://%s/sub/%s", scheme, r.Host, u.SubToken),
	})
}

// subscription serves a user's links as a base64 URI list, what v2rayN,
// Shadowrocket and friends import. No login: the token is the secret.
func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	u, found := s.d.Store.UserBySubToken(r.PathValue("token"))
	if !found {
		http.NotFound(w, r)
		return
	}
	links := linksFor(u, s.d.Store.Inbounds(), s.d.Store.Settings(), requestHost(r))
	var lines []string
	for _, l := range links {
		lines = append(lines, l.URI)
	}
	info := fmt.Sprintf("upload=%d; download=%d; total=%d", u.Up, u.Down, u.QuotaBytes)
	if u.ExpiresAt != nil {
		info += fmt.Sprintf("; expire=%d", u.ExpiresAt.Unix())
	}
	w.Header().Set("Subscription-Userinfo", info)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "12")
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))))
}

// ---- forwards --------------------------------------------------------------

func (s *Server) listForwards(w http.ResponseWriter, r *http.Request) {
	status := map[string]agentproto.ForwardStatus{}
	if a := s.currentAgent(); a != nil {
		for _, f := range a.ForwardStats() {
			status[f.Tag] = agentproto.ForwardStatus{Tag: f.Tag, Up: f.Up, RTTMillis: f.RTT.Milliseconds(), LastError: f.LastError,
				ActiveConn: f.ActiveConn, TotalConn: f.TotalConn, BytesIn: f.BytesIn, BytesOut: f.BytesOut}
		}
	}
	type row struct {
		spec.Forward
		Status *agentproto.ForwardStatus `json:"status"`
	}
	out := []row{}
	for _, f := range s.d.Store.ListForwards() {
		var st *agentproto.ForwardStatus
		if v, found := status[f.Tag]; found {
			st = &v
		}
		out = append(out, row{Forward: f, Status: st})
	}
	ok(w, out)
}

func (s *Server) createForward(w http.ResponseWriter, r *http.Request) {
	var f spec.Forward
	if err := decode(r, &f); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.PutForward(f, ""))
}

func (s *Server) updateForward(w http.ResponseWriter, r *http.Request) {
	var f spec.Forward
	if err := decode(r, &f); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.PutForward(f, r.PathValue("tag")))
}

func (s *Server) deleteForward(w http.ResponseWriter, r *http.Request) {
	storeErr(w, s.d.Store.DeleteForward(r.PathValue("tag")))
}

// ---- settings --------------------------------------------------------------

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	ok(w, s.d.Store.Settings())
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var v local.Settings
	if err := decode(r, &v); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.SetSettings(v))
}

func (s *Server) putAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.SetAdmin(in.Username, in.Password))
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("kind") {
	case "reality":
		priv, pub, err := realityKeys()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		ok(w, map[string]string{"private_key": priv, "public_key": pub, "short_id": authutil.Hex(4)})
	case "uuid":
		ok(w, map[string]string{"uuid": authutil.UUID()})
	case "password":
		ok(w, map[string]string{"password": authutil.Password(20)})
	case "ss2022":
		n := ss2022KeyLen(r.URL.Query().Get("cipher"))
		if n == 0 {
			n = 16
		}
		ok(w, map[string]string{"key": authutil.Base64(n)})
	default:
		fail(w, http.StatusNotFound, errors.New("unknown key kind"))
	}
}

// ---- mode ------------------------------------------------------------------

func (s *Server) adopt(w http.ResponseWriter, r *http.Request) {
	if s.d.Fixed != "" || s.d.Adopt == nil {
		fail(w, http.StatusConflict, errors.New("panel driver is fixed by the config file"))
		return
	}
	var in struct {
		URL      string `json:"url"`
		PairCode string `json:"pair_code"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	if !strings.HasPrefix(in.URL, "http://") && !strings.HasPrefix(in.URL, "https://") {
		fail(w, http.StatusBadRequest, errors.New("url must start with http:// or https://"))
		return
	}
	if strings.TrimSpace(in.PairCode) == "" {
		fail(w, http.StatusBadRequest, errors.New("pair code is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.d.Adopt(ctx, in.URL, strings.TrimSpace(in.PairCode)); err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	ok(w, map[string]bool{"ok": true})
}

func (s *Server) detach(w http.ResponseWriter, r *http.Request) {
	if s.d.Fixed != "" || s.d.Detach == nil {
		fail(w, http.StatusConflict, errors.New("panel driver is fixed by the config file"))
		return
	}
	var in struct {
		Keep bool `json:"keep"`
	}
	_ = decode(r, &in)
	if err := s.d.Detach(r.Context(), in.Keep); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ok(w, map[string]bool{"ok": true})
}
