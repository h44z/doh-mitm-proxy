# Go parameters
GOCMD=go
MODULENAME=doh_proxy
GOFILES:=$(shell go list ./... | grep -v /vendor/)
BUILDDIR=out

.PHONY: all test clean

all: dep validate build
build: dep
	$(GOCMD) build -o $(BUILDDIR)/dohpd cmd/dohpd/main.go
	$(GOCMD) build -o $(BUILDDIR)/dohc cmd/dohclient/main.go

validate:
	$(GOCMD) fmt $(GOFILES)
	$(GOCMD) vet $(GOFILES)
	$(GOCMD) test -race $(GOFILES)

dep:
	$(GOCMD) mod download

clean:
	$(GOCMD) clean
	rm -rf $(BUILDDIR)

setup-tls:
	openssl ecparam -genkey -name secp384r1 -out $(BUILDDIR)/server.key
	openssl req -new -x509 -sha256 -key server.key -out $(BUILDDIR)/server.crt -days 3650