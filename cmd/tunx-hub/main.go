// Command tunx-hub is the tunx controller: it stores the network in SQLite,
// serves the REST API and renders every node's tunxd and Xray config.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xiongyumail/tunx/internal/hub/api"
	"github.com/xiongyumail/tunx/internal/hub/auth"
	"github.com/xiongyumail/tunx/internal/hub/model"
	"github.com/xiongyumail/tunx/internal/hub/render"
	"github.com/xiongyumail/tunx/internal/hub/store"
)

const usage = `usage: tunx-hub <command> [flags] [args]

commands:
  init [-network NAME] [-admin NAME] [-password-file FILE]
                         create the database and the first administrator
                         (password from the file or the first line of stdin);
                         prints the TOTP secret once
  serve [-listen ADDR] [-tls-cert FILE -tls-key FILE] [-insecure-cookie]
                         serve the API (default 127.0.0.1:8780)
  render NODE            print the rendered configs of a node (JSON)
  import FILE            replace the network with a YAML file ("-": stdin)
  export FILE            write the network as YAML ("-": stdout)
  token NAME             create an API token and print it once
  enroll-token NODE      create a one-time enrolment token and print it

every command takes -db FILE (default tunx-hub.db); flags go before args
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "tunx-hub.db", "database file")
	var err error
	switch cmd {
	case "init":
		network := fs.String("network", "tunx", "network ID")
		admin := fs.String("admin", "admin", "administrator username")
		pwFile := fs.String("password-file", "", "file holding the administrator password")
		if fs.Parse(args) != nil || fs.NArg() != 0 {
			return 2
		}
		err = cmdInit(*db, *network, *admin, *pwFile, stdin, stdout)
	case "serve":
		listen := fs.String("listen", "127.0.0.1:8780", "listen address")
		cert := fs.String("tls-cert", "", "TLS certificate file")
		key := fs.String("tls-key", "", "TLS key file")
		insecure := fs.Bool("insecure-cookie", false, "send the session cookie over plain HTTP (behind a TLS proxy or on loopback)")
		if fs.Parse(args) != nil || fs.NArg() != 0 {
			return 2
		}
		err = cmdServe(*db, *listen, *cert, *key, *insecure, stderr)
	case "render", "import", "export", "token", "enroll-token":
		if fs.Parse(args) != nil || fs.NArg() != 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		err = withStore(*db, func(st *store.Store) error {
			return oneArg(st, cmd, fs.Arg(0), stdin, stdout, stderr)
		})
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "tunx-hub:", err)
		return 1
	}
	return 0
}

func withStore(path string, fn func(*store.Store) error) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("database %s: %w (run tunx-hub init first)", path, err)
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(st)
}

func cmdInit(path, network, admin, pwFile string, stdin io.Reader, stdout io.Writer) error {
	var pw string
	if pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			return err
		}
		pw = strings.TrimRight(string(b), "\r\n")
	} else {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if len(pw) < 12 {
		return errors.New("the administrator password must have at least 12 characters")
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if n, err := st.AdminCount(ctx); err != nil {
		return err
	} else if n > 0 {
		return errors.New("the database already has an administrator")
	}
	if _, err := st.Update(ctx, "cli", func(s *model.Spec) error {
		if s.Network.Name == "" {
			s.Network.Name = network
		}
		return nil
	}); err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	if err := st.CreateAdmin(ctx, store.Admin{Username: admin, PasswordHash: hash, TOTPSecret: secret}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "database %s ready; administrator %q created\n", path, admin)
	fmt.Fprintf(stdout, "TOTP secret (shown once): %s\n", secret)
	fmt.Fprintf(stdout, "TOTP URI: %s\n", auth.TOTPURI("tunx-hub", admin, secret))
	return nil
}

func cmdServe(path, listen, cert, key string, insecure bool, stderr io.Writer) error {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if (cert == "") != (key == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	return withStore(path, func(st *store.Store) error {
		srv := &api.Server{Store: st, Log: log, SecureCookie: !insecure}
		hs := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		if host, _, _ := net.SplitHostPort(listen); cert == "" && !isLoopback(host) {
			log.Warn("serving plain HTTP on a non-loopback address; put a TLS proxy in front or use -tls-cert")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		errc := make(chan error, 1)
		go func() {
			if cert != "" {
				errc <- hs.ServeTLS(ln, cert, key)
			} else {
				errc <- hs.Serve(ln)
			}
		}()
		log.Info("serving", "addr", ln.Addr().String(), "tls", cert != "")
		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
		}
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	})
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oneArg(st *store.Store, cmd, arg string, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx := context.Background()
	switch cmd {
	case "render":
		spec, err := st.Spec(ctx)
		if err != nil {
			return err
		}
		b, err := render.Node(spec, arg)
		if err != nil {
			return err
		}
		for _, w := range b.Warnings {
			fmt.Fprintln(stderr, "warning:", w)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	case "import":
		var b []byte
		var err error
		if arg == "-" {
			b, err = io.ReadAll(stdin)
		} else {
			b, err = os.ReadFile(arg)
		}
		if err != nil {
			return err
		}
		spec, err := model.ParseYAML(b)
		if err != nil {
			return err
		}
		changes, err := st.Import(ctx, "cli", spec)
		if err != nil {
			return err
		}
		for _, c := range changes {
			fmt.Fprintf(stdout, "%s %s %s\n", c.Action, c.Kind, c.Name)
		}
		fmt.Fprintf(stdout, "%d changes\n", len(changes))
		return nil
	case "export":
		spec, err := st.Spec(ctx)
		if err != nil {
			return err
		}
		b, err := model.MarshalYAML(spec)
		if err != nil {
			return err
		}
		if arg == "-" {
			_, err = stdout.Write(b)
			return err
		}
		return os.WriteFile(arg, b, 0o600)
	case "token":
		tok, err := auth.NewToken(api.APITokenPrefix)
		if err != nil {
			return err
		}
		if err := st.CreateAPIToken(ctx, "cli", arg, auth.HashToken(tok)); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tok)
		return nil
	case "enroll-token":
		tok, err := auth.NewToken(api.EnrollPrefix)
		if err != nil {
			return err
		}
		expires := st.Now().Add(24 * time.Hour)
		if err := st.CreateEnrollToken(ctx, "cli", arg, auth.HashToken(tok), expires); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tok)
		fmt.Fprintf(stderr, "valid until %s; the node posts it to /api/enroll\n", expires.UTC().Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}
