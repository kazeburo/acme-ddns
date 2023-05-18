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
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
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
	TTL        time.Duration `long:"ttl" default:"1h" description:"ttl for TXT"`
	Expiration time.Duration `long:"expiration" default:"3h" description:"expiration time for cache TXT record"`
	Zone       string        `long:"zone" required:"true" description:"zone name for dynamic dns"`
	KeyName    []string      `long:"keyname" description:"Name of TSIG key"`
	Secret     []string      `long:"secret" description:"secret of TSIG key"`
	NSAddr     string        `long:"ns-addr" default:"127.0.0.1" description:"NS record value of the zone"`
	cache      *cache.Cache
	tsigSecret map[string]string
	nsAddr     net.IP
}

func (opt *Opt) handleQuery(m *dns.Msg, r *dns.Msg) {
	// quetionは1つ
	for _, q := range r.Question {
		if q.Qtype == dns.TypeA && q.Name == opt.Zone {
			a := new(dns.A)
			a.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(opt.TTL.Seconds()),
			}
			a.A = opt.nsAddr
			m.Answer = append(m.Answer, a)
			return
		}
		if q.Qtype == dns.TypeNS && q.Name == opt.Zone {
			a := new(dns.NS)
			a.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    uint32(opt.TTL.Seconds()),
			}
			a.Ns = opt.Zone
			m.Answer = append(m.Answer, a)
			return
		}
		if q.Qtype != dns.TypeTXT {
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
		soa.Ns = opt.Zone
		soa.Mbox = opt.Zone
		soa.Serial = 1
		soa.Refresh = 3600
		soa.Retry = 900
		soa.Expire = 2419200
		soa.Minttl = 30
		m.Ns = append(m.Ns, soa)

		val, ok := opt.cache.Get(q.Name)
		if !ok {
			m.Rcode = dns.RcodeNameError
			return
		}
		txt, ok := val.([]string)
		if !ok {
			m.Rcode = dns.RcodeServerFailure
			return
		}
		a := new(dns.TXT)
		a.Hdr = dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    uint32(opt.TTL.Seconds()),
		}
		a.Txt = txt
		m.Answer = append(m.Answer, a)
	}
}

func (opt *Opt) handleUpdates(w dns.ResponseWriter, m *dns.Msg, r *dns.Msg) {
	if opt.tsigSecret != nil && len(opt.tsigSecret) > 0 {
		if m.IsTsig() != nil {
			m.Rcode = dns.RcodeRefused
			return
		}
		if err := w.TsigStatus(); err != nil {
			m.Rcode = dns.RcodeRefused
			return
		}
	}
	// quetionは1つ
	for _, q := range r.Question {
		// nsは複数個ある
		for _, rr := range r.Ns {
			opt.updateRecord(rr, &q)
		}
	}
}

func (opt *Opt) updateRecord(r dns.RR, q *dns.Question) error {
	txt, ok := r.(*dns.TXT)
	if !ok {
		return fmt.Errorf("not txt")
	}
	if r.Header().Class == dns.ClassINET {
		// log.Printf("addRecord key:%s value:%v", txt.Header().Name, txt.Txt)
		if err := opt.cache.Add(r.Header().Name, txt.Txt, cache.DefaultExpiration); err != nil {
			log.Printf("failed to addRecord key:%s value:%v error:%v", txt.Header().Name, txt.Txt, err)
		}
	} else {
		// remove
		// log.Printf("deleteRecord key:%s", txt.Header().Name)
		opt.cache.Delete(r.Header().Name)
	}
	return nil
}

func (opt *Opt) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		m.Authoritative = true
		opt.handleQuery(m, r)
	case dns.OpcodeUpdate:
		opt.handleUpdates(w, m, r)
	}

	if opt.tsigSecret != nil && len(opt.tsigSecret) > 0 {
		if r.IsTsig() != nil {
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
	}

	w.WriteMsg(m)
}

func acceptUpdateQueries(dh dns.Header) dns.MsgAcceptAction {
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

	opt.nsAddr = net.ParseIP(opt.NSAddr)
	if opt.nsAddr == nil {
		log.Printf("failed to parse ns-addr")
		os.Exit(StatusCodeWARNING)
	}

	opt.cache = cache.New(opt.Expiration, 1*time.Minute)
	dns.HandleFunc(opt.Zone, opt.handleRequest)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server := &dns.Server{
		Addr:          opt.Listen,
		Net:           "udp",
		MsgAcceptFunc: acceptUpdateQueries,
	}
	opt.tsigSecret = map[string]string{}
	for i := range opt.KeyName {
		k := opt.KeyName[i]
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		opt.tsigSecret[k] = opt.Secret[i]
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

	err = server.ListenAndServe()
	if err != nil {
		log.Printf("%+v", err)
	}

}
