package internal

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	jsonDNS "github.com/m13253/dns-over-https/json-dns"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type dohProxy struct {
	cfg      *Configuration
	serveMux *http.ServeMux
	upstream *dns.Client
}

type dnsRequest struct {
	request       *dns.Msg
	response      *dns.Msg
	transactionID uint16
	isECSRequest  bool
	errCode       int
	errText       string
}

func NewProxy(cfg *Configuration) *dohProxy {
	var client *dns.Client

	if cfg.Upstream.Protocol == "DNS" {
		client = &dns.Client{
			Net:     "udp",
			UDPSize: dns.DefaultMsgSize,
			Timeout: cfg.Upstream.TimeOut,
		}
	} else if cfg.Upstream.Protocol == "DOT" {
		client = &dns.Client{
			Net:       "tcp-tls",
			Timeout:   cfg.Upstream.TimeOut,
			TLSConfig: &tls.Config{InsecureSkipVerify: cfg.Upstream.AllowInsecure},
		}
	} else {
		log.Fatalf("Unsupported upstream protocol %s", cfg.Upstream.Protocol)
	}
	proxy := &dohProxy{
		cfg:      cfg,
		serveMux: http.NewServeMux(),
		upstream: client,
	}

	// Set up HTTP handler
	proxy.serveMux.HandleFunc(cfg.Core.RequestPath, proxy.handlerFunc)

	return proxy
}

func (p *dohProxy) Run() {
	// Start HTTP server in background
	go func() {
		addr := p.cfg.Core.ListenAddress + ":" + strconv.Itoa(p.cfg.Core.ListenPort)
		var err error
		if p.cfg.Core.Cert != "" || p.cfg.Core.Key != "" {
			err = http.ListenAndServeTLS(addr, p.cfg.Core.Cert, p.cfg.Core.Key, p.serveMux)
		} else {
			err = http.ListenAndServe(addr, p.serveMux)
		}
		if err != nil {
			log.Fatalf("Failed to start server: %s", err.Error())
		}
	}()
}

func (p *dohProxy) handlerFunc(w http.ResponseWriter, r *http.Request) {
	// Setup response headers
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.Header().Set("Server", "DoH-Proxy/1.0.0 (University of Innsbruck, Security and Privacy Lab)")
	w.Header().Set("X-Powered-By", "DoH-Proxy/1.0.0 (University of Innsbruck, Security and Privacy Lab)")

	if r.Method == "OPTIONS" {
		w.Header().Set("Content-Length", "0")
		return
	}

	// Check request content type, currently only dns-message is supported
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		log.Warnf("Invalid content type received: %s", contentType)
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// Parse accept header, check if application/dns-message is supported. If not, return an error
	var responseType string
	for _, responseCandidate := range strings.Split(r.Header.Get("Accept"), ",") {
		responseCandidate = strings.SplitN(responseCandidate, ";", 2)[0]
		if responseCandidate == "application/dns-message" {
			responseType = "application/dns-message"
			break
		} else if responseCandidate == "application/*" {
			responseType = "application/dns-message"
			break
		} else if responseCandidate == "*/*" {
			responseType = "application/dns-message"
			break
		}
	}
	if responseType != "application/dns-message" {
		log.Warn("Accept header does not contain application/dns-message")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// Extract the DNS request from the HTTP request
	dnsReq := p.parseDNSRequest(r)
	if dnsReq.errCode != 0 {
		log.Warnf("Failed to parse DNS request: %d | %s", dnsReq.errCode, dnsReq.errText)
		w.WriteHeader(dnsReq.errCode)
		return
	}

	// Perform the DNS query on the upstream DNS server
	if err := p.performDNSQuery(dnsReq); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Strip ESNI key
	if p.cfg.Core.StripESNIKey && IsESNIKeyRequest(dnsReq.request) {
		log.Infof(" --> Removing ESNI Key from response: %s", dns.RcodeToString[dnsReq.response.Rcode])
		CraftESNIResponse(dnsReq)
	}

	// Write back the DNS response
	p.generateDoHResponse(w, dnsReq)
}

func (p *dohProxy) parseDNSRequest(r *http.Request) *dnsRequest {
	// Search for the DNS field, POST and PUT body parameters take precedence over URL query string values
	requestBase64 := r.FormValue("dns")
	requestBinary, err := base64.RawURLEncoding.DecodeString(requestBase64) // decode using base64url
	if err != nil {
		return &dnsRequest{
			errCode: http.StatusBadRequest,
			errText: fmt.Sprintf("Failed to decode base64url: \"dns\" = %q", requestBase64),
		}
	}

	// Load DNS request from body if it was not set in the GET parameter
	if len(requestBinary) == 0 && (r.Header.Get("Content-Type") == "application/dns-message") {
		requestBinary, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return &dnsRequest{
				errCode: http.StatusBadRequest,
				errText: fmt.Sprintf("Failed to read request body: %s", err.Error()),
			}
		}
	}

	// Still no DNS request, that's an error!
	if len(requestBinary) == 0 {
		return &dnsRequest{
			errCode: http.StatusBadRequest,
			errText: fmt.Sprintf("Missing argument value: \"dns\""),
		}
	}

	// Parse the real DNS request message
	msg := new(dns.Msg)
	if err := msg.Unpack(requestBinary); err != nil {
		return &dnsRequest{
			errCode: http.StatusBadRequest,
			errText: fmt.Sprintf("Failed to parse DNS packet: %s", err.Error()),
		}
	}

	// Log request
	if p.cfg.Core.Verbose && len(msg.Question) > 0 {
		question := &msg.Question[0]
		questionName := question.Name
		questionClass := strconv.FormatUint(uint64(question.Qclass), 10)
		questionType := strconv.FormatUint(uint64(question.Qtype), 10)

		if qClass, ok := dns.ClassToString[question.Qclass]; ok {
			questionClass = qClass
		}
		if qType, ok := dns.TypeToString[question.Qtype]; ok {
			questionType = qType
		}

		clientIP := p.getClientIPAddress(r)
		if clientIP != nil {
			log.Infof("%s - %s - [%s] \"%s %s %s\"", r.RemoteAddr, clientIP, time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionClass, questionType)
		} else {
			log.Infof("%s - - [%s] \"%s %s %s\"", r.RemoteAddr, time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionClass, questionType)
		}
	}

	transactionID := msg.Id // Save current transaction id
	msg.Id = dns.Id()       // Generate a new random transaction id that is sent to the upstream server
	isECSRequest := false

	// Extended DNS support
	if p.cfg.Core.SupportEDNS {
		opt := msg.IsEdns0() // Check if EDNS is enabled (searches an OPT resource record)
		if opt == nil {
			opt = new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(dns.DefaultMsgSize)              // Increase default msg size of 512 bytes
			opt.SetDo(false)                                // DNSSEC OK, settings this to false tells the resolver to ignore DNSSEC validation
			msg.Extra = append([]dns.RR{opt}, msg.Extra...) // append OPT resource record to extra records
		}

		// EDNS0-Client-Subnet (GeoDNS)
		var edns0Subnet *dns.EDNS0_SUBNET
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0SUBNET {
				edns0Subnet = option.(*dns.EDNS0_SUBNET)
				break
			}
		}
		isECSRequest = edns0Subnet != nil
		if edns0Subnet == nil {
			ednsClientFamily := uint16(0)
			ednsClientAddress := p.getClientIPAddress(r)
			ednsClientNetmask := uint8(255)
			if ednsClientAddress != nil { // nil means: skip ECS extension
				if ipv4 := ednsClientAddress.To4(); ipv4 != nil {
					ednsClientFamily = 1
					ednsClientAddress = ipv4
					ednsClientNetmask = 24
				} else {
					ednsClientFamily = 2
					ednsClientNetmask = 56
				}
				edns0Subnet = new(dns.EDNS0_SUBNET)
				edns0Subnet.Code = dns.EDNS0SUBNET
				edns0Subnet.Family = ednsClientFamily
				edns0Subnet.SourceNetmask = ednsClientNetmask
				edns0Subnet.SourceScope = 0
				edns0Subnet.Address = ednsClientAddress
				opt.Option = append(opt.Option, edns0Subnet)
			}
		}
	}

	return &dnsRequest{
		request:       msg,
		transactionID: transactionID,
		isECSRequest:  isECSRequest,
	}
}

func (p *dohProxy) performDNSQuery(req *dnsRequest) error {
	var err error
	req.response, _, err = p.upstream.Exchange(req.request, p.cfg.Upstream.Host)
	if err != nil {
		log.Warnf("DNS error from upstream %s: %s", p.cfg.Upstream.Host, err.Error())
	}

	// Log request
	if p.cfg.Core.Verbose && err == nil {
		log.Infof(" --> [%s] %s", dns.RcodeToString[req.response.Rcode], time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	}

	return err
}

func (p *dohProxy) generateDoHResponse(w http.ResponseWriter, req *dnsRequest) {
	// Parse DNS response to JSON for easier processing
	respJSON := jsonDNS.Marshal(req.response)

	// Create binary response body
	req.response.Id = req.transactionID // Set response ID to the request ID
	respBytes, err := req.response.Pack()
	if err != nil {
		log.Warnf("DNS packet construct failure with upstream: %s", err.Error())
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/dns-message")
	now := time.Now().UTC().Format(http.TimeFormat)
	w.Header().Set("Date", now)
	w.Header().Set("Last-Modified", now)
	w.Header().Set("Vary", "Accept")

	if respJSON.HaveTTL {
		if req.isECSRequest {
			w.Header().Set("Cache-Control", "private, max-age="+strconv.FormatUint(uint64(respJSON.LeastTTL), 10))
		} else {
			w.Header().Set("Cache-Control", "public, max-age="+strconv.FormatUint(uint64(respJSON.LeastTTL), 10))
		}
		w.Header().Set("Expires", respJSON.EarliestExpires.Format(http.TimeFormat))
	}

	// Pass through server-failure
	if respJSON.Status == dns.RcodeServerFailure {
		log.Warnf("Received server failure from upstream: %v", req.response)
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Write binary body to the response stream
	if _, err = w.Write(respBytes); err != nil {
		log.Errorf("Failed to write to client: %s", err.Error())
	}
}

func (p *dohProxy) getClientIPAddress(r *http.Request) net.IP {
	// Check if EDNS0-Client-Subnet should be skipped
	if noEcs := r.URL.Query().Get("no_ecs"); strings.ToLower(noEcs) == "true" {
		return nil
	}

	// First check X-Forwarded-For Header
	XForwardedFor := r.Header.Get("X-Forwarded-For")
	if XForwardedFor != "" {
		for _, addr := range strings.Split(XForwardedFor, ",") {
			addr = strings.TrimSpace(addr)
			ip := net.ParseIP(addr)
			if jsonDNS.IsGlobalIP(ip) {
				return ip
			}
		}
	}

	// Next check X-Real-IP header
	XRealIP := r.Header.Get("X-Real-IP")
	if XRealIP != "" {
		addr := strings.TrimSpace(XRealIP)
		ip := net.ParseIP(addr)
		if jsonDNS.IsGlobalIP(ip) {
			return ip
		}
	}

	// Lastly use the remote address
	remoteAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return nil
	}
	if ip := remoteAddr.IP; jsonDNS.IsGlobalIP(ip) {
		return ip
	}

	return nil
}
