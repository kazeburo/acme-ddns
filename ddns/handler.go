package ddns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type DDNS struct {
	TsigSecretMap map[string]string
	Zone          string
	NSName        string
	NSAddr        net.IP
	TTL           time.Duration
	Cache         *cache.Cache
	Logger        *slog.Logger
}

var (
	DefaultExpiration = 3 * time.Hour
	DefaultNSAddr     = net.ParseIP("127.0.0.1")
	DefaultNSName     = "ns"
	DefaultTTL        = 300 * time.Second
)

type DDNSOption func(*DDNS)

func TsigSecretMap(secrets map[string]string) DDNSOption {
	return func(ddns *DDNS) {
		ddns.TsigSecretMap = secrets
	}
}

func Zone(zone string) DDNSOption {
	return func(ddns *DDNS) {
		ddns.Zone = zone
	}
}

func NSName(nsName string) DDNSOption {
	return func(ddns *DDNS) {
		ddns.NSName = nsName
	}
}

func NSAddr(nsAddr net.IP) DDNSOption {
	return func(ddns *DDNS) {
		ddns.NSAddr = nsAddr
	}
}

func TTL(ttl time.Duration) DDNSOption {
	return func(ddns *DDNS) {
		ddns.TTL = ttl
	}
}

func Cache(cache *cache.Cache) DDNSOption {
	return func(ddns *DDNS) {
		ddns.Cache = cache
	}
}

func Logger(logger *slog.Logger) DDNSOption {
	return func(ddns *DDNS) {
		ddns.Logger = logger
	}
}

func New(ops ...DDNSOption) (*DDNS, error) {
	ddns := &DDNS{
		NSAddr: DefaultNSAddr,
		NSName: DefaultNSName,
		TTL:    DefaultTTL,
	}
	for _, op := range ops {
		op(ddns)
	}
	if ddns.Zone == "" {
		return nil, fmt.Errorf("zone is required")
	}
	if !strings.HasSuffix(ddns.Zone, ".") {
		ddns.Zone = ddns.Zone + "."
	}
	if !strings.HasSuffix(ddns.NSName, ".") {
		ddns.NSName = ddns.NSName + "."
	}
	if !strings.HasSuffix(ddns.NSName, ddns.Zone) {
		ddns.NSName = ddns.NSName + ddns.Zone
	}
	if ddns.TsigSecretMap == nil {
		ddns.TsigSecretMap = map[string]string{}
	}
	if ddns.Cache == nil {
		ddns.Cache = cache.New(DefaultExpiration, 1*time.Minute)
	}
	if ddns.Logger == nil {
		ddns.Logger = slog.Default()
	}
	return ddns, nil
}

func (ddns *DDNS) tsigEnabled() bool {
	return ddns.TsigSecretMap != nil && len(ddns.TsigSecretMap) > 0
}

func (ddns *DDNS) handleQuery(m *dns.Msg, r *dns.Msg, logger *slog.Logger) {
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		return
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name)

	logger.Info(
		"handleQuery",
		slog.String("qname", q.Name),
		slog.String("class", dns.ClassToString[q.Qclass]),
		slog.String("type", dns.TypeToString[q.Qtype]),
	)

	if !strings.HasSuffix(qName, ddns.Zone) {
		m.Rcode = dns.RcodeRefused
		return
	}

	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:   q.Name,
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		Ttl:    uint32(ddns.TTL.Seconds()),
	}
	soa.Ns = ddns.NSName
	soa.Mbox = ddns.NSName
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
			Ttl:    uint32(ddns.TTL.Seconds()),
		}
		a.Ns = ddns.NSName
		m.Answer = append(m.Answer, a)
		return
	}

	if q.Qtype == dns.TypeA && (qName == ddns.NSName || qName == ddns.Zone) {
		a := new(dns.A)
		a.Hdr = dns.RR_Header{
			Name:   qName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(ddns.TTL.Seconds()),
		}
		a.A = ddns.NSAddr
		m.Answer = append(m.Answer, a)
		return
	}

	if q.Qtype != dns.TypeTXT {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
		return
	}

	val, ok := ddns.Cache.Get(qName)
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
		Ttl:    uint32(ddns.TTL.Seconds()),
	}
	a.Txt = txt
	m.Answer = append(m.Answer, a)
}

func (ddns *DDNS) handleUpdates(m *dns.Msg, r *dns.Msg, logger *slog.Logger) {
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		return
	}

	// nsは複数個ある
	for _, rr := range r.Ns {
		logger.Info(
			"updateRequest",
			slog.String("qname", rr.Header().Name),
			slog.String("class", dns.ClassToString[rr.Header().Class]),
			slog.String("type", dns.TypeToString[rr.Header().Rrtype]),
		)
		rcode, err := ddns.updateRecord(rr)
		if err != nil {
			logger.Error(
				"updateRequest failed",
				slog.String("qname", rr.Header().Name),
				slog.String("class", dns.ClassToString[rr.Header().Class]),
				slog.String("type", dns.TypeToString[rr.Header().Rrtype]),
				"err", err,
			)
			m.Rcode = rcode
		}
	}
}

func (ddns *DDNS) updateRecord(r dns.RR) (int, error) {
	txt, ok := r.(*dns.TXT)
	if !ok {
		return dns.RcodeRefused, fmt.Errorf("not txt rr")
	}

	qName := strings.ToLower(r.Header().Name)

	if !strings.HasSuffix(qName, ddns.Zone) {
		return dns.RcodeRefused, fmt.Errorf("invalid zone")
	}

	if r.Header().Class == dns.ClassINET {
		// add new
		if err := ddns.Cache.Add(qName, txt.Txt, cache.DefaultExpiration); err != nil {
			return dns.RcodeServerFailure, err
		}
	} else {
		// remove
		ddns.Cache.Delete(qName)
	}

	return dns.RcodeSuccess, nil
}

func (ddns *DDNS) validateTsig(w dns.ResponseWriter, r *dns.Msg) error {
	if !ddns.tsigEnabled() {
		return nil
	}
	if r.IsTsig() == nil {
		return fmt.Errorf("tsig required")
	}
	if err := w.TsigStatus(); err != nil {
		return err
	}
	return nil
}

func (ddns *DDNS) setTsig(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) error {
	if !ddns.tsigEnabled() {
		return nil
	}
	if r.IsTsig() == nil {
		return nil
	}
	if err := w.TsigStatus(); err != nil {
		return err
	}
	m.SetTsig(
		r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name,
		dns.HmacSHA256,
		300,
		time.Now().Unix(),
	)
	return nil
}

func (ddns *DDNS) HandleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true

	logger := ddns.Logger.With(
		slog.String("remote_addr", w.RemoteAddr().String()),
		slog.String("opcode", dns.OpcodeToString[r.Opcode]),
	)

	switch r.Opcode {
	case dns.OpcodeQuery:
		ddns.handleQuery(m, r, logger)
	case dns.OpcodeUpdate:
		if err := ddns.validateTsig(w, r); err != nil {
			logger.Warn("validateTsig", "err", err)
			m.Rcode = dns.RcodeRefused
		} else {
			ddns.handleUpdates(m, r, logger)
		}
	}

	if err := ddns.setTsig(w, r, m); err != nil {
		logger.Warn("setTsig", "err", err)
	}

	w.WriteMsg(m)
}

func (ddns *DDNS) UpdateMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
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
