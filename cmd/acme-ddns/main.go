package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
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
	cache      *cache.Cache
	tsigSecret map[string]string
	nsAddr     net.IP
}

func (opt *Opt) tsgiEnabled() bool {
	return opt.tsigSecret != nil && len(opt.tsigSecret) > 0
}

func (opt *Opt) handleQuery(m *dns.Msg, r *dns.Msg) {
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		return
	}

	q := r.Question[0]
	log.Printf("Query name:%s type:%s", q.Name, dns.TypeToString[q.Qtype])
	qName := strings.ToLower(q.Name)

	if !strings.HasSuffix(qName, opt.Zone) {
		m.Rcode = dns.RcodeRefused
		return
	}

	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:   q.Name,
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		Ttl:    uint32(opt.TTL.Seconds()),
	}
	soa.Ns = opt.NSName
	soa.Mbox = opt.NSName
	soa.Serial = 1
	soa.Refresh = 3600
	soa.Retry = 900
	soa.Expire = 2419200
	soa.Minttl = 30

	if q.Qtype == dns.TypeSOA {
		m.Answer = append(m.Answer, soa)
		return
	}

	if q.Qtype == dns.TypeNS {
		a := new(dns.NS)
		a.Hdr = dns.RR_Header{
			Name:   qName,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    uint32(opt.TTL.Seconds()),
		}
		a.Ns = opt.NSName
		m.Answer = append(m.Answer, a)
		return
	}

	if q.Qtype == dns.TypeA && (qName == opt.NSName || qName == opt.Zone) {
		a := new(dns.A)
		a.Hdr = dns.RR_Header{
			Name:   qName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(opt.TTL.Seconds()),
		}
		a.A = opt.nsAddr
		m.Answer = append(m.Answer, a)
		return
	}

	if q.Qtype != dns.TypeTXT {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
		return
	}

	val, ok := opt.cache.Get(qName)
	if !ok {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
		return
	}
	txt, ok := val.([]string)
	if !ok {
		m.Rcode = dns.RcodeServerFailure
		return
	}

	a := new(dns.TXT)
	a.Hdr = dns.RR_Header{
		Name:   qName,
		Rrtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		Ttl:    uint32(opt.TTL.Seconds()),
	}
	a.Txt = txt
	m.Answer = append(m.Answer, a)
}

func (opt *Opt) handleUpdates(m *dns.Msg, r *dns.Msg) {
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		return
	}

	q := r.Question[0]
	// nsは複数個ある
	for _, rr := range r.Ns {
		rcode, err := opt.updateRecord(rr, &q)
		if err != nil {
			log.Printf("failed to update record :%v", err)
			m.Rcode = rcode
		}
	}
}

func (opt *Opt) updateRecord(r dns.RR, q *dns.Question) (int, error) {
	txt, ok := r.(*dns.TXT)
	if !ok {
		return dns.RcodeRefused, fmt.Errorf("not txt rr")
	}

	log.Printf("update request to %s class:%s", r.Header().Name, dns.ClassToString[r.Header().Class])

	qName := strings.ToLower(r.Header().Name)

	if !strings.HasSuffix(qName, opt.Zone) {
		return dns.RcodeRefused, fmt.Errorf("invalid zone")
	}

	if r.Header().Class == dns.ClassINET {
		// add new
		if err := opt.cache.Add(qName, txt.Txt, cache.DefaultExpiration); err != nil {
			return dns.RcodeServerFailure, fmt.Errorf("failed to addRecord key:%s value:%v error:%v", qName, txt.Txt, err)
		}
	} else {
		// remove
		opt.cache.Delete(qName)
	}

	return dns.RcodeSuccess, nil
}

func (opt *Opt) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		opt.handleQuery(m, r)
	case dns.OpcodeUpdate:
		if opt.tsgiEnabled() {
			if r.IsTsig() == nil {
				log.Printf("tsig required")
				m.Rcode = dns.RcodeRefused
			}
			if err := w.TsigStatus(); err != nil {
				log.Printf("tsig status: %v", err)
				m.Rcode = dns.RcodeRefused
			}
		}
		if m.Rcode != dns.RcodeRefused {
			opt.handleUpdates(m, r)
		}
	}

	if opt.tsgiEnabled() && r.IsTsig() != nil {
		if err := w.TsigStatus(); err != nil {
			log.Printf("isTsigStatus: %+v", err)
		} else {
			m.SetTsig(
				r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name,
				dns.HmacSHA256,
				300,
				time.Now().Unix(),
			)
		}
	}

	w.WriteMsg(m)
}

func (opt *Opt) updateMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	queryReplyBit := uint16(1 << 15) // nolint:gomnd

	if isReply := dh.Bits&queryReplyBit != 0; isReply {
		return dns.MsgIgnore
	}
	opcode := int(dh.Bits>>11) & 0xF
	// ADD: OpcodeUpdate
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 {
		return dns.MsgReject
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	// ADD: ignore when OpcodeUpdate
	if dh.Nscount > 1 && opcode != dns.OpcodeUpdate {
		return dns.MsgReject
	}

	if dh.Arcount > 2 {
		return dns.MsgReject
	}

	return dns.MsgAccept
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
	if !strings.HasSuffix(opt.Zone, ".") {
		opt.Zone = opt.Zone + "."
	}

	if key := os.Getenv("TSIG_KEYNAME"); key != "" {
		opt.KeyName = strings.Split(key, ":")
	}
	if secret := os.Getenv("TSIG_SECRET"); secret != "" {
		opt.Secret = strings.Split(secret, ":")
	}
	if len(opt.KeyName) != len(opt.Secret) {
		log.Printf("length of keyname and secret not match")
		os.Exit(StatusCodeWARNING)
	}

	if !strings.HasPrefix(opt.NSName, ".") {
		opt.NSName = opt.NSName + "."
	}
	if !strings.HasPrefix(opt.NSName, "."+opt.Zone) {
		opt.NSName = opt.NSName + opt.Zone
	}

	opt.nsAddr = net.ParseIP(opt.NSAddr)
	if opt.nsAddr == nil {
		log.Printf("failed to parse ns-addr")
		os.Exit(StatusCodeWARNING)
	}

	opt.tsigSecret = map[string]string{}
	for i := range opt.KeyName {
		k := opt.KeyName[i]
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		opt.tsigSecret[k] = opt.Secret[i]
	}

	opt.cache = cache.New(opt.Expiration, 1*time.Minute)
	dns.HandleFunc(".", opt.handleRequest)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eg := errgroup.Group{}
	for _, net := range []string{"udp", "tcp"} {
		server := &dns.Server{
			Addr:          opt.Listen,
			Net:           net,
			MsgAcceptFunc: opt.updateMsgAcceptFunc,
		}

		if len(opt.tsigSecret) > 0 {
			server.TsigSecret = opt.tsigSecret
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
		log.Printf("%+v", err)
	}
}
