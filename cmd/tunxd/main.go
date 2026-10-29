// Command tunxd is the tunx node daemon.
//
//	tunxd run -c config.json     run the node
//	tunxd check -c config.json   validate a config and print the TUN setup
//	tunxd keygen                 print a new key pair
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/forward"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage:
  tunxd run -c config.json     run the node
  tunxd check -c config.json   validate a config and print the TUN setup
  tunxd keygen                 print a new key pair
`

// run executes a subcommand; ctx ending stops `run`.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "keygen":
		return keygen(stdout, stderr)
	case "check", "run":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(stderr)
		file := fs.String("c", "/etc/tunx/tunxd.json", "config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cfg, err := config.Load(*file)
		if err != nil {
			fmt.Fprintln(stderr, "tunxd:", err)
			return 1
		}
		if args[0] == "check" {
			return check(cfg, stdout)
		}
		return serve(ctx, cfg, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "tunxd: unknown command %q\n%s", args[0], usage)
	return 2
}

func keygen(stdout, stderr io.Writer) int {
	priv, pub, err := config.GenerateKey()
	if err != nil {
		fmt.Fprintln(stderr, "tunxd:", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]string{"private_key": priv, "public_key": pub})
	return 0
}

// check prints a summary and the commands that set up the TUN device.
func check(cfg *config.Config, w io.Writer) int {
	fmt.Fprintf(w, "config ok: node %s, network %q, %d peers, %d routes, %d policy rules\n",
		cfg.Node, cfg.Network, len(cfg.Peers), len(cfg.Routes), len(cfg.Policy))
	pub, _ := config.PublicKey(cfg.PublicKey()).MarshalText()
	fmt.Fprintf(w, "public key: %s\n", pub)
	if t := cfg.TUN; t != nil {
		fmt.Fprintln(w, "\n# tunxd creates the TUN device; addresses and routes are set by the operator:")
		if t.MTU != 0 {
			fmt.Fprintf(w, "ip link set dev %s mtu %d\n", t.Name, t.MTU)
		}
		for _, a := range t.Addresses {
			fmt.Fprintf(w, "ip addr add %s dev %s\n", a, t.Name)
		}
		fmt.Fprintf(w, "ip link set dev %s up\n", t.Name)
		for _, p := range t.Capture {
			fam := "-4"
			if p.Addr().Is6() {
				fam = "-6"
			}
			fmt.Fprintf(w, "ip %s route replace %s dev %s\n", fam, p, t.Name)
		}
	}
	return 0
}

func serve(ctx context.Context, cfg *config.Config, stderr io.Writer) int {
	level, _ := cfg.Level()
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	n, err := forward.Start(cfg, forward.Options{Logger: log})
	if err != nil {
		log.Error("start failed", "err", err)
		return 1
	}
	<-ctx.Done()
	log.Info("shutting down")
	n.Close()
	return 0
}
