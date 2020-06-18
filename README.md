DNS-over-HTTPS Proxy
====================

Server software to query DNS over HTTPS, using [IETF DNS-over-HTTPS (RFC 8484)](https://www.rfc-editor.org/rfc/rfc8484.txt).

This server allows the administrator to strip any ESNI keys from the DNS responses.

## Compiling
- Install [Go](https://golang.org), at least version 1.14.
- Checkout this project:
  ```bash
  git clone https://github.com/h44z/doh-mitm-proxy
  cd doh-mitm-proxy
  ```
- To build the program, type:
  ```bash
  make
  ```
- To run the program, type:
  ```bash
  out/dohpd
  ```