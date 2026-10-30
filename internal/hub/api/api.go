// Package api is the REST API of tunx-hub. Administrators authenticate
// with username, password and TOTP and get a session cookie; automation
// uses API tokens; nodes use their config token. All bodies are JSON
// except import and export, which are YAML.
package api

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xiongyumail/tunx/internal/hub/auth"
	"github.com/xiongyumail/tunx/internal/hub/model"
	"github.com/xiongyumail/tunx/internal/hub/render"
	"github.com/xiongyumail/tunx/internal/hub/store"
)

// Token prefixes tell the token kinds apart.
const (
	APITokenPrefix  = "tunx_at_"
	NodeTokenPrefix = "tunx_nt_"
	EnrollPrefix    = "tunx_et_"
	SessionCookie   = "tunx_session"
	// CSRFHeader must be present on cookie-authenticated requests that
	// change state; browsers cannot send it cross-site without CORS.
	CSRFHeader = "X-Tunx-CSRF"
)

const maxBody = 4 << 20

// Server serves the API.
type Server struct {
	Store *store.Store
	Log   *slog.Logger
	// SecureCookie sets the Secure flag on the session cookie.
	SecureCookie bool
	SessionTTL   time.Duration // default 12h
	EnrollTTL    time.Duration // default 24h

	mu       sync.Mutex
	failures map[string]*failure
}

// failure counts recent failed logins of one username.
type failure struct {
	count int
	last  time.Time // last failure
	until time.Time // locked until
}

// principal is the authenticated caller.
type principal struct {
	actor  string // for the audit log
	admin  bool
	node   string // set for a node token
	cookie bool
}

type ctxKey struct{}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/enroll", s.enroll)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })

	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.authed(true, h)) }
	admin("POST /api/logout", s.logout)
	admin("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"actor": who(r).actor})
	})
	admin("GET /api/network", s.getNetwork)
	admin("PUT /api/network", s.putNetwork)
	admin("GET /api/export", s.export)
	admin("POST /api/import", s.importYAML)
	admin("GET /api/audit", s.audit)
	admin("GET /api/tokens", s.listTokens)
	admin("POST /api/tokens", s.createToken)
	admin("DELETE /api/tokens/{name}", s.deleteToken)
	admin("POST /api/nodes/{name}/enroll-token", s.enrollToken)
	admin("GET /api/clients/{name}/share", s.share)
	admin("GET /api/{kind}", s.list)
	admin("POST /api/{kind}", s.create)
	admin("GET /api/{kind}/{name}", s.get)
	admin("PUT /api/{kind}/{name}", s.put)
	admin("DELETE /api/{kind}/{name}", s.delete)
	mux.Handle("GET /api/nodes/{name}/config", s.authed(false, s.nodeConfig))
	return s.logRequests(mux)
}

func (s *Server) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		h.ServeHTTP(sw, r)
		s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func who(r *http.Request) principal { p, _ := r.Context().Value(ctxKey{}).(principal); return p }

// authed resolves the caller. adminOnly rejects node tokens.
func (s *Server) authed(adminOnly bool, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if adminOnly && !p.admin {
			writeError(w, http.StatusForbidden, "administrator access required")
			return
		}
		if p.cookie && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(CSRFHeader) == "" {
			writeError(w, http.StatusForbidden, "missing "+CSRFHeader+" header")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func (s *Server) authenticate(r *http.Request) (principal, error) {
	ctx := r.Context()
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		tok = strings.TrimSpace(tok)
		switch {
		case strings.HasPrefix(tok, APITokenPrefix):
			name, err := s.Store.APITokenByHash(ctx, auth.HashToken(tok))
			if err != nil {
				return principal{}, err
			}
			return principal{actor: "token:" + name, admin: true}, nil
		case strings.HasPrefix(tok, NodeTokenPrefix):
			node, err := s.Store.NodeByToken(ctx, auth.HashToken(tok))
			if err != nil {
				return principal{}, err
			}
			return principal{actor: "node:" + node, node: node}, nil
		}
		return principal{}, errors.New("unknown token")
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return principal{}, err
	}
	user, err := s.Store.Session(ctx, auth.HashToken(c.Value))
	if err != nil {
		return principal{}, err
	}
	return principal{actor: "admin:" + user, admin: true, cookie: true}, nil
}

// dummyHash keeps the cost of a login for an unknown user equal to that
// of a wrong password.
var dummyHash = sync.OnceValue(func() string { h, _ := auth.HashPassword("unused"); return h })

const (
	maxFailures = 5
	lockout     = time.Minute
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	now := s.Store.Now()
	s.mu.Lock()
	if s.failures == nil {
		s.failures = map[string]*failure{}
	}
	f := s.failures[req.Username]
	locked := f != nil && now.Before(f.until)
	s.mu.Unlock()
	if locked {
		writeError(w, http.StatusTooManyRequests, "too many failed logins; try again later")
		return
	}

	a, err := s.Store.Admin(ctx, req.Username)
	ok := false
	if err == nil {
		ok = auth.CheckPassword(a.PasswordHash, req.Password)
		if ok {
			var step int64
			step, ok = auth.VerifyTOTP(a.TOTPSecret, req.TOTP, now, a.TOTPLast)
			if ok {
				ok, err = s.Store.UseTOTPStep(ctx, a.Username, step)
			}
		}
	} else if errors.Is(err, store.ErrNotFound) {
		auth.CheckPassword(dummyHash(), req.Password)
		err = nil
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if !ok {
		s.mu.Lock()
		if len(s.failures) > 10000 {
			clear(s.failures) // bound memory under username spraying
		}
		f := s.failures[req.Username]
		if f == nil || now.Sub(f.last) > lockout {
			f = &failure{}
			s.failures[req.Username] = f
		}
		f.count++
		f.last = now
		if f.count >= maxFailures {
			f.until, f.count = now.Add(lockout), 0
		}
		s.mu.Unlock()
		s.Store.LogEvent(ctx, "login:"+req.Username, "login-failed", "admin", req.Username, map[string]any{"remote": r.RemoteAddr})
		writeError(w, http.StatusUnauthorized, "invalid username, password or code")
		return
	}
	s.mu.Lock()
	delete(s.failures, req.Username)
	s.mu.Unlock()

	tok, err := auth.NewToken("")
	if err != nil {
		s.internal(w, err)
		return
	}
	ttl := cmp.Or(s.SessionTTL, 12*time.Hour)
	if err := s.Store.CreateSession(ctx, auth.HashToken(tok), a.Username, now.Add(ttl)); err != nil {
		s.internal(w, err)
		return
	}
	s.Store.LogEvent(ctx, "admin:"+a.Username, "login", "admin", a.Username, map[string]any{"remote": r.RemoteAddr})
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: tok, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, 200, map[string]string{"actor": "admin:" + a.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		s.Store.DeleteSession(r.Context(), auth.HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getNetwork(w http.ResponseWriter, r *http.Request) {
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, spec.Network)
}

func (s *Server) putNetwork(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var n model.Network
	if err := model.DecodeJSON(b, &n); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.update(w, r, func(spec *model.Spec) error { spec.Network = n; return nil }, func(spec *model.Spec) any { return spec.Network })
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if !model.ValidKind(kind) {
		writeError(w, 404, "unknown kind "+strconv.Quote(kind))
		return
	}
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := []any{}
	for _, it := range spec.Items(kind) {
		out = append(out, it.Obj)
	}
	writeJSON(w, 200, out)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	kind, name := r.PathValue("kind"), r.PathValue("name")
	if !model.ValidKind(kind) {
		writeError(w, 404, "unknown kind "+strconv.Quote(kind))
		return
	}
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	obj, err := spec.Get(kind, name)
	if err != nil {
		writeError(w, 404, fmt.Sprintf("%s %q not found", kind, name))
		return
	}
	writeJSON(w, 200, obj)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	s.write(w, r, r.PathValue("kind"), "", true)
}
func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	s.write(w, r, r.PathValue("kind"), r.PathValue("name"), false)
}

var (
	errExists   = errors.New("already exists")
	errMismatch = errors.New("the name in the body must match the path")
)

// write creates (POST, must not exist) or replaces (PUT) one object.
func (s *Server) write(w http.ResponseWriter, r *http.Request, kind, pathName string, create bool) {
	if !model.ValidKind(kind) {
		writeError(w, 404, "unknown kind "+strconv.Quote(kind))
		return
	}
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var probe struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		writeError(w, 400, "invalid JSON body: "+err.Error())
		return
	}
	s.update(w, r, func(spec *model.Spec) error {
		if pathName != "" && probe.Name != pathName {
			return errMismatch
		}
		if _, err := spec.Get(kind, probe.Name); create && err == nil {
			return fmt.Errorf("%s %q: %w", kind, probe.Name, errExists)
		}
		if _, err := spec.Put(kind, b); err != nil {
			return &store.ValidationError{Err: err}
		}
		return nil
	}, func(spec *model.Spec) any { o, _ := spec.Get(kind, probe.Name); return o })
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	kind, name := r.PathValue("kind"), r.PathValue("name")
	if !model.ValidKind(kind) {
		writeError(w, 404, "unknown kind "+strconv.Quote(kind))
		return
	}
	s.update(w, r, func(spec *model.Spec) error { return spec.Delete(kind, name) }, nil)
}

type updateResult struct {
	Changes []store.Change `json:"changes"`
	Object  any            `json:"object,omitempty"`
}

// update applies fn to the network and responds with the changes and,
// when result is set, the resulting object.
func (s *Server) update(w http.ResponseWriter, r *http.Request, fn func(*model.Spec) error, result func(*model.Spec) any) {
	changes, err := s.Store.Update(r.Context(), who(r).actor, fn)
	var ve *store.ValidationError
	switch {
	case err == nil:
	case errors.As(err, &ve), errors.Is(err, errMismatch):
		writeError(w, 400, err.Error())
		return
	case errors.Is(err, errExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, model.ErrNotFound):
		writeError(w, 404, "not found")
		return
	default:
		s.internal(w, err)
		return
	}
	res := updateResult{Changes: changes}
	if changes == nil {
		res.Changes = []store.Change{}
	}
	if result != nil {
		spec, err := s.Store.Spec(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		res.Object = result(spec)
	}
	writeJSON(w, 200, res)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	b, err := model.MarshalYAML(spec)
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (s *Server) importYAML(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	spec, err := model.ParseYAML(b)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if r.URL.Query().Get("dry_run") == "1" {
		changes, err := s.Store.PreviewImport(r.Context(), spec)
		var ve *store.ValidationError
		if errors.As(err, &ve) {
			writeError(w, 400, err.Error())
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		if changes == nil {
			changes = []store.Change{}
		}
		writeJSON(w, 200, updateResult{Changes: changes})
		return
	}
	s.update(w, r, func(cur *model.Spec) error { *cur = *spec; return nil }, nil)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.Store.Audit(r.Context(), limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, entries)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.Store.APITokens(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, toks)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	tok, err := auth.NewToken(APITokenPrefix)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.Store.CreateAPIToken(r.Context(), who(r).actor, req.Name, auth.HashToken(tok)); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"name": req.Name, "token": tok})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteAPIToken(r.Context(), who(r).actor, r.PathValue("name")); errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "not found")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enrollToken(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("name")
	tok, err := auth.NewToken(EnrollPrefix)
	if err != nil {
		s.internal(w, err)
		return
	}
	expires := s.Store.Now().Add(cmp.Or(s.EnrollTTL, 24*time.Hour))
	if err := s.Store.CreateEnrollToken(r.Context(), who(r).actor, node, auth.HashToken(tok), expires); errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, fmt.Sprintf("node %q not found", node))
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"node": node, "token": tok, "expires_at": expires.UTC().Format(time.RFC3339)})
}

// EnrollResponse is returned once to an enrolling node.
type EnrollResponse struct {
	Node       string `json:"node"`
	Network    string `json:"network"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	NodeToken  string `json:"node_token"`
	ConfigPath string `json:"config_path"`
	KeyFile    string `json:"key_file"`
}

// enroll exchanges a one-time token for the node's key pair (generated
// here, never stored) and its config token.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.internal(w, err)
		return
	}
	nodeTok, err := auth.NewToken(NodeTokenPrefix)
	if err != nil {
		s.internal(w, err)
		return
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	node, err := s.Store.Enroll(r.Context(), auth.HashToken(req.Token), pubB64, auth.HashToken(nodeTok))
	if errors.Is(err, store.ErrBadEnrollToken) {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, EnrollResponse{
		Node: node, Network: spec.Network.Name,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()), PublicKey: pubB64,
		NodeToken: nodeTok, ConfigPath: "/api/nodes/" + node + "/config", KeyFile: render.KeyFile,
	})
}

func (s *Server) nodeConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if p := who(r); !p.admin && p.node != name {
		writeError(w, http.StatusForbidden, "this token belongs to another node")
		return
	}
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	b, err := render.Node(spec, name)
	if errors.Is(err, model.ErrNotFound) {
		writeError(w, 404, fmt.Sprintf("node %q not found", name))
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	etag := `"` + b.Revision + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, 200, b)
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	spec, err := s.Store.Spec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	link, err := render.ShareLink(spec, r.PathValue("name"))
	if errors.Is(err, model.ErrNotFound) {
		writeError(w, 404, "not found")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"link": link})
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large or unreadable")
		return nil, false
	}
	return b, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, ok := readBody(w, r)
	if !ok {
		return false
	}
	if err := model.DecodeJSON(b, v); err != nil {
		writeError(w, 400, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("internal error", "err", err)
	writeError(w, 500, "internal error")
}
