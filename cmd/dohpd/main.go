package main

import (
	"doh_proxy/internal"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// Wait for SIGINT or SIGTERM and quit the program
func awaitShutdownSignal() {
	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received.
	s := <-sig
	log.Infof("Signal (%v) received, stopping", s)
	os.Exit(0)
}

// DoH Proxy Daemon
func main() {
	// Setup logger
	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = "2006-01-02 15:04:05"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true // for docker
	log.SetFormatter(Formatter)

	// Parse command line flags
	configPath := flag.String("config", "config.yml", "path to the configuration file")
	flag.Parse()

	// Load configuration file / environment variables
	cfg, err := internal.LoadCustomConfiguration(*configPath)
	if err != nil {
		dir, _ := os.Getwd()
		log.Debug("Working directory: ", dir)
		log.Errorf("Configuration reading failed: %s", err.Error())
		os.Exit(1)
	}

	secure := "insecure"
	stripESNI := ""
	if cfg.Core.Cert != "" && cfg.Core.Key != "" {
		secure = "secure"
	}
	if cfg.Core.StripESNIKey {
		stripESNI = ", strip-esni"
	}
	log.Infof("Starting DoH Proxy, listening on %s:%d (%s%s), upstream %s (%s)", cfg.Core.ListenAddress,
		cfg.Core.ListenPort, secure, stripESNI, cfg.Upstream.Host, cfg.Upstream.Protocol)

	// Start DoH proxy
	proxy := internal.NewProxy(cfg)
	proxy.Run()

	// Wait until shutdown signal is received
	awaitShutdownSignal()
}
