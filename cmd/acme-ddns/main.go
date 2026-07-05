package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/acme-ddns/ddns"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/errgroup"
)

const (
	StatusCodeOK      = 0
	StatusCodeWARNING = 1
)

// version by Makefile
var version string

type Opt struct {
	Version    bool          `short:"v" long:"version" description:"Show version"`
	Listen     string        `long:"listen" default:":8053" description:"address for listen"`
	TTL        time.Duration `long:"ttl" default:"5m" description:"ttl for TXT"`
	Expiration time.Duration `long:"expiration" default:"3h" description:"expiration time for cache TXT record"`
	Zone       string        `long:"zone" required:"true" description:"zone name for dynamic dns"`
	KeyName    []string      `long:"keyname" description:"Name of TSIG key"`
	Secret     []string      `long:"secret" description:"secret of TSIG key"`
	NSName     string        `long:"ns-name" default:"ns" description:"NS record name of the zone"`
	NSAddr     string        `long:"ns-addr" default:"127.0.0.1" description:"NS record value of the zone"`
}

func main() {
	opt := Opt{}
	psr := flags.NewParser(&opt, flags.HelpFlag|flags.PassDoubleDash)
	_, err := psr.Parse()
	if opt.Version {
		fmt.Printf(`%s %s
Compiler: %s %s
`,
			os.Args[0],
			version,
			runtime.Compiler,
			runtime.Version())
		os.Exit(StatusCodeOK)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(StatusCodeWARNING)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if key := os.Getenv("TSIG_KEYNAME"); key != "" {
		opt.KeyName = strings.Split(key, ":")
	}
	if secret := os.Getenv("TSIG_SECRET"); secret != "" {
		opt.Secret = strings.Split(secret, ":")
	}
	if len(opt.KeyName) != len(opt.Secret) {
		logger.Warn("length of keyname and secret not match")
		os.Exit(StatusCodeWARNING)
	}

	tsigSecretMap := map[string]string{}
	for i := range opt.KeyName {
		k := opt.KeyName[i]
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		tsigSecretMap[k] = opt.Secret[i]
	}

	nsAddr := net.ParseIP(opt.NSAddr)
	if nsAddr == nil {
		logger.Warn("failed to parse ns-addr")
		os.Exit(StatusCodeWARNING)
	}

	cache := cache.New(opt.Expiration, 1*time.Minute)

	handler, err := ddns.New(
		ddns.TsigSecretMap(tsigSecretMap),
		ddns.Zone(opt.Zone),
		ddns.NSName(opt.NSName),
		ddns.NSAddr(nsAddr),
		ddns.TTL(opt.TTL),
		ddns.Cache(cache),
		ddns.Logger(logger),
	)
	if err != nil {
		logger.Warn("failed to create handler", "err", err)
		os.Exit(StatusCodeWARNING)
	}
	dns.HandleFunc(".", handler.HandleRequest)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eg := errgroup.Group{}
	for _, net := range []string{"udp", "tcp"} {
		server := &dns.Server{
			Addr:          opt.Listen,
			Net:           net,
			MsgAcceptFunc: handler.UpdateMsgAcceptFunc,
		}

		if len(tsigSecretMap) > 0 {
			server.TsigSecret = tsigSecretMap
		}

		go func() {
			<-ctx.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.ShutdownContext(ctx)
		}()

		eg.Go(func() error {
			return server.ListenAndServe()
		})
	}
	if err := eg.Wait(); err != nil {
		logger.Warn("serve/shutdown", "err", err)
	}
}
