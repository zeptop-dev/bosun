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
	"github.com/zeptop-dev/bosun/pkg/subscription"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/logring"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
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
	// Updater checks and applies bosun releases; nil disables the feature.
	Updater *selfupdate.Client
	// Certs reports automatic certificates; nil when disabled.
	Certs *certs.Manager
}

// Server is the panel HTTP handler.
type Server struct {
	d     Deps
	mux   *http.ServeMux
	start time.Time

	mu       sync.Mutex
	agent    *agent.Agent
	sessions *sessionStore
	failed   map[string]failure
	// doctorRep is the last on-demand self-check, served again for 30 s.
	doctorRep *agentproto.DoctorReport
	doctorAt  time.Time
}

type failure struct {
	count int
	last  time.Time
}

// New builds the handler.
func New(d Deps) *Server {
	s := &Server{d: d, mux: http.NewServeMux(), start: time.Now(), sessions: newSessionStore(d.Store.Path(), sessionTTL), failed: map[string]failure{}}
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
	m.HandleFunc("POST /api/2fa/setup", auth(s.totpSetup))
	m.HandleFunc("POST /api/2fa/enable", auth(s.totpEnable))
	m.HandleFunc("POST /api/2fa/disable", auth(s.totpDisable))
	m.HandleFunc("GET /api/tokens", auth(s.listTokens))
	m.HandleFunc("POST /api/tokens", auth(s.createToken))
	m.HandleFunc("DELETE /api/tokens/{id}", auth(s.deleteToken))
	m.HandleFunc("POST /api/keys/{kind}", auth(s.keys))

	m.HandleFunc("POST /api/mode/adopt", auth(s.adopt))
	m.HandleFunc("POST /api/mode/detach", auth(s.detach))

	m.HandleFunc("GET /api/update", auth(s.updateCheck))
	m.HandleFunc("POST /api/update/apply", auth(s.updateApply))
	m.HandleFunc("POST /api/update/rollback", auth(s.updateRollback))
	m.HandleFunc("POST /api/restart", auth(s.restart))

	s.extraRoutes()
	s.doctorBackupRoutes()
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

// ipAllowed applies the panel allow-list (empty = everyone).
func (s *Server) ipAllowed(r *http.Request) bool {
	list := s.d.Store.Settings().PanelAllowCIDRs
	if len(list) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP(r))
	if ip == nil {
		return false
	}
	for _, c := range list {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if ip.Equal(net.ParseIP(c)) {
				return true
			}
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.ipAllowed(r) {
			fail(w, http.StatusForbidden, errors.New("your address is not on the panel allow-list"))
			return
		}
		// Personal API token (scripts): same access as the login.
		if tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")); tok != "" {
			if s.d.Store.CheckAPIToken(tok) {
				next(w, r)
				return
			}
			fail(w, http.StatusUnauthorized, errors.New("invalid API token"))
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, errors.New("not signed in"))
			return
		}
		if !s.sessions.Valid(c.Value) {
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
	var in struct{ Username, Password, Code string }
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if !s.ipAllowed(r) {
		fail(w, http.StatusForbidden, errors.New("your address is not on the panel allow-list"))
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
	// Second factor: the password alone is not enough once TOTP is on.
	if secret, enabled := s.d.Store.TOTP(); enabled {
		if in.Code == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{"totp": true, "error": "authenticator code required"})
			return
		}
		if !authutil.VerifyTOTP(secret, in.Code, time.Now()) {
			s.mu.Lock()
			s.failed[ip] = failure{count: f.count + 1, last: time.Now()}
			s.mu.Unlock()
			fail(w, http.StatusUnauthorized, errors.New("wrong authenticator code"))
			return
		}
	}
	tok := authutil.Token(32)
	s.mu.Lock()
	delete(s.failed, ip)
	s.mu.Unlock()
	s.sessions.Add(tok)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.d.Secure, MaxAge: int(sessionTTL.Seconds())})
	ok(w, map[string]any{"username": in.Username, "version": s.d.Version})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	ok(w, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	mode, _, _ := s.d.Store.Mode()
	_, totp := s.d.Store.TOTP()
	ok(w, map[string]any{"username": s.d.Store.Username(), "version": s.d.Version, "mode": mode, "fixed": s.d.Fixed, "totp": totp})
}

// totpSetup mints a pending secret; nothing is enforced until totpEnable
// proves the authenticator produces matching codes.
func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	secret := authutil.NewTOTPSecret()
	if err := s.d.Store.SetTOTP(secret, false); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	ok(w, map[string]string{"secret": secret, "uri": authutil.TOTPURI("bosun", s.d.Store.Username(), secret)})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	_ = decode(r, &in)
	secret, _ := s.d.Store.TOTP()
	if secret == "" || !authutil.VerifyTOTP(secret, in.Code, time.Now()) {
		fail(w, http.StatusBadRequest, errors.New("wrong code"))
		return
	}
	storeErr(w, s.d.Store.SetTOTP(secret, true))
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	_ = decode(r, &in)
	secret, enabled := s.d.Store.TOTP()
	if enabled && !authutil.VerifyTOTP(secret, in.Code, time.Now()) {
		fail(w, http.StatusBadRequest, errors.New("wrong code"))
		return
	}
	storeErr(w, s.d.Store.SetTOTP("", false))
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) { ok(w, s.d.Store.ListAPITokens()) }

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	_ = decode(r, &in)
	tok, plain, err := s.d.Store.CreateAPIToken(in.Name)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ok(w, map[string]any{"id": tok.ID, "name": tok.Name, "token": plain})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.DeleteAPIToken(id))
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
	certList := []certs.Status{}
	if s.d.Certs != nil {
		certList = s.d.Certs.Status()
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
		"certs": certList, "pings": s.probeResults(),
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
	// OverDevices is set while the user is held back for exceeding the
	// device limit; OverDevicesUntil says when the hold ends.
	OverDevices      bool       `json:"over_devices"`
	OverDevicesUntil *time.Time `json:"over_devices_until,omitempty"`
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
		row := userRow{User: u, Online: ips, Usable: u.Usable(now)}
		if until, held := rt.OverDevices[u.ID]; held {
			row.OverDevices, row.OverDevicesUntil = true, &until
		}
		out = append(out, row)
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
		"links":   linksFor(u, s.d.Store.Inbounds(), s.d.Store.Settings(), requestHost(r), s.d.Store.ListIngresses()...),
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
	// The document format follows the client (User-Agent or ?client=):
	// Clash/mihomo YAML, sing-box JSON, Surge/Loon/QX/Stash/Surfboard
	// dialects, else a base64 URI list.
	settings := s.d.Store.Settings()
	lines := linesFor(u, s.d.Store.Inbounds(), settings, requestHost(r), s.d.Store.ListIngresses()...)
	if strings.TrimSpace(settings.ExtraLinks) != "" {
		extra, _ := subscription.ParseList(settings.ExtraLinks)
		lines = append(lines, extra...)
	}
	acct := subscription.Account{Upload: u.Up, Download: u.Down, Total: u.QuotaBytes}
	if u.ExpiresAt != nil {
		acct.Expire = u.ExpiresAt.Unix()
	}
	rd := subscription.Pick(r.URL.Query().Get("client"), r.UserAgent())
	body, err := rd.Render(lines, acct)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(settings.NodeName)
	if name == "" {
		name = "bosun"
	}
	w.Header().Set("Content-Type", rd.ContentType())
	w.Header().Set("Content-Disposition", "attachment; filename="+asciiName(name)+"; filename*=UTF-8''"+url.PathEscape(name))
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(name)))
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", acct.Upload, acct.Download, acct.Total, acct.Expire))
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
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
	if len(v.PanelAllowCIDRs) > 0 {
		ip := net.ParseIP(clientIP(r))
		hit := false
		for _, c := range v.PanelAllowCIDRs {
			if !strings.Contains(c, "/") {
				hit = hit || ip.Equal(net.ParseIP(strings.TrimSpace(c)))
			} else if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n.Contains(ip) {
				hit = true
			}
		}
		if !hit {
			fail(w, http.StatusBadRequest, fmt.Errorf("the allow-list would lock you out: your address %s is not in it", ip))
			return
		}
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
	case "wireguard":
		priv, pub, err := wg.Keypair()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		ok(w, map[string]string{"private_key": priv, "public_key": pub})
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

// ---- self-update -------------------------------------------------------------

func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	if s.d.Updater == nil {
		fail(w, http.StatusNotFound, errors.New("self-update disabled"))
		return
	}
	ok(w, s.d.Updater.Check(r.Context(), r.URL.Query().Get("force") == "1"))
}

// updateApply installs the latest (or requested) release and restarts.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	if s.d.Updater == nil {
		fail(w, http.StatusNotFound, errors.New("self-update disabled"))
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	_ = decode(r, &in)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ver, err := s.d.Updater.Apply(ctx, in.Version)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, selfupdate.ErrInContainer) || errors.Is(err, selfupdate.ErrUpToDate) {
			code = http.StatusConflict
		}
		fail(w, code, err)
		return
	}
	s.d.Log.Warn("bosun updated; restarting", "version", ver)
	ok(w, map[string]any{"installed": ver, "restarting": true})
	selfupdate.Restart(500 * time.Millisecond)
}

func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if s.d.Updater == nil {
		fail(w, http.StatusNotFound, errors.New("self-update disabled"))
		return
	}
	ver, err := s.d.Updater.Rollback()
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	s.d.Log.Warn("bosun rolled back; restarting", "version", ver)
	ok(w, map[string]any{"installed": ver, "restarting": true})
	selfupdate.Restart(500 * time.Millisecond)
}

// restart exits so the supervisor starts the binary again.
func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	s.d.Log.Warn("restart requested from the web panel")
	ok(w, map[string]bool{"restarting": true})
	selfupdate.Restart(500 * time.Millisecond)
}

// asciiName keeps a profile name safe for the plain Content-Disposition
// filename (clients that ignore filename* still get something readable).
func asciiName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_.-")
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	if out == "" {
		out = "bosun"
	}
	return out
}
