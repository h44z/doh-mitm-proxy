package internal

import (
	"strings"

	"github.com/miekg/dns"
)

const ESNIKeyIdentifier = "_esni."

func IsESNIKeyRequest(msg *dns.Msg) bool {
	if len(msg.Question) > 0 {
		question := &msg.Question[0]
		questionName := question.Name

		if strings.HasPrefix(questionName, ESNIKeyIdentifier) {
			return true
		}
	}

	return false
}

func CraftESNIResponse(dnsReq *dnsRequest) {
	// Check if response already is a NX-DOMAIN
	if dnsReq.response.Rcode == dns.RcodeNameError {
		return
	}

	// Create a new NX-DOMAIN record
	resp := new(dns.Msg)
	resp.SetRcode(dnsReq.request, dns.RcodeNameError)
	resp.Ns = dnsReq.response.Ns

	dnsReq.response = resp
}
