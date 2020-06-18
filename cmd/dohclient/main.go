package main

import (
	"flag"
	"os"

	"github.com/h44z/go-doh-client"
)

// Sample DoH client for testing purpose
func main() {
	// Parse command line flags
	resolverURL := flag.String("r", "http://localhost:8080/dns-query", "resolver url, e.g.: http://localhost:8080/dns-query")
	queryType := flag.String("t", "TXT", "query type, e.g.: A or TXT")
	domain := flag.String("d", "_esni.cloudflare.com", "domain, e.g.: example.com")

	flag.Parse()

	resolver := doh.Resolver{
		URL:           *resolverURL, // Change this with your favourite DoH-compliant resolver.
		Class:         doh.IN,
		AllowInsecure: true,
	}

	// Perform lookup
	switch *queryType {
	case "A":
		a, _, err := resolver.LookupA(*domain)
		if err != nil {
			println("A:", err.Error())
			os.Exit(-1)
		}
		println("A:", a[0].IP4)
	case "AAAA":
		a, _, err := resolver.LookupAAAA(*domain)
		if err != nil {
			println("AAAA:", err.Error())
			os.Exit(-1)
		}
		println("AAAA:", a[0].IP6)
	case "TXT":
		txt, _, err := resolver.LookupTXT(*domain)
		if err != nil {
			println("TXT:", err.Error())
			os.Exit(-1)
		}
		println("TXT:", txt[0].TXT)
	}
}
