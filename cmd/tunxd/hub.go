package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
)

const (
	hubStateFile = "hub.json"
	tunxdFile    = "tunxd.json"
	xrayFile     = "xray.json"
	maxHubBody   = 4 << 20
)

type hubState struct {
	Hub        string `json:"hub"`
	Node       string `json:"node"`
	NodeToken  string `json:"node_token"`
	ConfigPath string `json:"config_path"`
	KeyFile    string `json:"key_file"`
	ETag       string `json:"etag,omitempty"`
}

type enrollResponse struct {
	Node       string `json:"node"`
	Network    string `json:"network"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	NodeToken  string `json:"node_token"`
	ConfigPath string `json:"config_path"`
	KeyFile    string `json:"key_file"`
}

type nodeBundle struct {
	Node     string          `json:"node"`
	Revision string          `json:"revision"`
	Tunxd    json.RawMessage `json:"tunxd"`
	Xray     json.RawMessage `json:"xray"`
	Warnings []string        `json:"warnings,omitempty"`
}

func enrollCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hub := fs.String("hub", "", "hub base URL")
	tokenFile := fs.String("token-file", "", "one-time token file, or - for stdin")
	dir := fs.String("dir", "/etc/tunx", "configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *hub == "" || *tokenFile == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "tunxd: enroll needs -hub and -token-file")
		return 2
	}
	base, err := hubURL(*hub)
	if err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	var reply enrollResponse
	if err := hubJSON(ctx, http.MethodPost, base.ResolveReference(&url.URL{Path: "/api/enroll"}), "", map[string]string{"token": token}, &reply, nil); err != nil {
		fmt.Fprintln(stderr, "tunxd: enroll:", err)
		return 1
	}
	if err := validateEnrollment(reply); err != nil {
		fmt.Fprintln(stderr, "tunxd: enroll:", err)
		return 1
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	state := hubState{Hub: strings.TrimRight(base.String(), "/"), Node: reply.Node, NodeToken: reply.NodeToken, ConfigPath: reply.ConfigPath, KeyFile: reply.KeyFile}
	if err := atomicWrite(filepath.Join(*dir, reply.KeyFile), []byte(reply.PrivateKey+"\n"), 0o600); err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	if err := saveState(*dir, &state); err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	changed, revision, err := pullConfig(ctx, *dir, &state)
	if err != nil {
		fmt.Fprintf(stderr, "tunxd: enrolled as %s, but initial config pull failed: %v\n", reply.Node, err)
		return 1
	}
	fmt.Fprintf(stdout, "enrolled node %s; config revision %s (changed=%t)\n", reply.Node, revision, changed)
	return 0
}

func pullCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "/etc/tunx", "configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "tunxd: pull takes no arguments")
		return 2
	}
	state, err := loadState(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	changed, revision, err := pullConfig(ctx, *dir, state)
	if err != nil {
		fmt.Fprintln(stderr, "tunxd: pull:", err)
		return 1
	}
	if changed {
		fmt.Fprintf(stdout, "config updated: revision %s\n", revision)
	} else {
		fmt.Fprintln(stdout, "config unchanged")
	}
	return 0
}

func pullConfig(ctx context.Context, dir string, state *hubState) (bool, string, error) {
	base, err := hubURL(state.Hub)
	if err != nil {
		return false, "", err
	}
	ref, err := url.Parse(state.ConfigPath)
	if err != nil {
		return false, "", fmt.Errorf("config path: %w", err)
	}
	if ref.IsAbs() || ref.Host != "" || ref.RawQuery != "" || ref.Fragment != "" || !strings.HasPrefix(ref.Path, "/api/") {
		return false, "", errors.New("config path is not a local hub API path")
	}
	var bundle nodeBundle
	var hdr http.Header
	status, err := hubJSONStatus(ctx, http.MethodGet, base.ResolveReference(ref), state.NodeToken, nil, &bundle, &hdr, state.ETag)
	if err != nil {
		return false, "", err
	}
	if status == http.StatusNotModified {
		return false, strings.Trim(state.ETag, `"`), nil
	}
	if bundle.Node != state.Node || bundle.Revision == "" {
		return false, "", errors.New("hub returned a bundle for the wrong node or without a revision")
	}
	etag := hdr.Get("ETag")
	if etag == "" || etag != `"`+bundle.Revision+`"` {
		return false, "", errors.New("hub returned a missing or inconsistent ETag")
	}
	tunxd, err := indentJSON(bundle.Tunxd)
	if err != nil {
		return false, "", fmt.Errorf("tunxd config: %w", err)
	}
	xray, err := indentJSON(bundle.Xray)
	if err != nil {
		return false, "", fmt.Errorf("xray config: %w", err)
	}
	parsed, err := config.Parse(tunxd)
	if err != nil {
		return false, "", err
	}
	if parsed.Node != state.Node || parsed.PrivateKeyFile != state.KeyFile {
		return false, "", errors.New("rendered tunxd config has the wrong node or key file")
	}
	if err := parsed.Validate(dir); err != nil {
		return false, "", fmt.Errorf("rendered tunxd config: %w", err)
	}
	if err := atomicWrite(filepath.Join(dir, xrayFile), xray, 0o600); err != nil {
		return false, "", err
	}
	if err := atomicWrite(filepath.Join(dir, tunxdFile), tunxd, 0o600); err != nil {
		return false, "", err
	}
	state.ETag = etag
	if err := saveState(dir, state); err != nil {
		return false, "", err
	}
	return true, bundle.Revision, nil
}

func hubURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid hub URL %q", raw)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("hub URL must use HTTPS unless it is loopback")
		}
	}
	return u, nil
}

func readToken(file string) (string, error) {
	var r io.Reader = os.Stdin
	var f *os.File
	var err error
	if file == "-" {
	} else {
		f, err = os.Open(file)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" || len(t) > 4096 {
		return "", errors.New("token file is empty or too large")
	}
	return t, nil
}

func validateEnrollment(r enrollResponse) error {
	if r.Node == "" || r.NodeToken == "" || r.ConfigPath == "" || r.KeyFile == "" || filepath.Base(r.KeyFile) != r.KeyFile || r.KeyFile == "." {
		return errors.New("hub returned an incomplete or unsafe enrolment response")
	}
	priv, err := config.ParsePrivateKey(r.PrivateKey)
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		return errors.New("hub returned mismatched node keys")
	}
	if p, err := url.Parse(r.ConfigPath); err != nil || !strings.HasPrefix(p.Path, "/api/") || p.Host != "" {
		return errors.New("hub returned an invalid config path")
	}
	return nil
}

func indentJSON(raw json.RawMessage) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errors.New("expected a JSON object")
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func loadState(dir string) (*hubState, error) {
	b, err := os.ReadFile(filepath.Join(dir, hubStateFile))
	if err != nil {
		return nil, err
	}
	var s hubState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	if s.Hub == "" || s.Node == "" || s.NodeToken == "" || s.ConfigPath == "" || s.KeyFile == "" {
		return nil, errors.New("hub state is incomplete")
	}
	if filepath.Base(s.KeyFile) != s.KeyFile || s.KeyFile == "." {
		return nil, errors.New("hub state has an unsafe key file")
	}
	return &s, nil
}

func saveState(dir string, s *hubState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWrite(filepath.Join(dir, hubStateFile), b, 0o600)
}

func atomicWrite(name string, b []byte, mode os.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(name), ".tunx-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { os.Remove(tmp) }()
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

func hubJSON(ctx context.Context, method string, u *url.URL, bearer string, body, out any, hdr *http.Header) error {
	_, err := hubJSONStatus(ctx, method, u, bearer, body, out, hdr, "")
	return err
}

func hubJSONStatus(ctx context.Context, method string, u *url.URL, bearer string, body, out any, hdr *http.Header, etag string) (int, error) {
	var src io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		src = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), src)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tunxd")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if hdr != nil {
		*hdr = resp.Header.Clone()
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxHubBody+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(b) > maxHubBody {
		return resp.StatusCode, errors.New("hub response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return resp.StatusCode, errors.New(e.Error)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}
