package internal

import (
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Core struct {
		ListenAddress string `yaml:"listen_address" envconfig:"CORE_LISTEN_ADDRESS"` // Listening IP address, keep empty to listen on all interfaces
		ListenPort    int    `yaml:"listen_port" envconfig:"CORE_LISTEN_PORT"`       // Listening Port
		Cert          string `yaml:"cert" envconfig:"CORE_CERT"`                     // Path to cert, if empty, plain HTTP will be used
		Key           string `yaml:"key" envconfig:"CORE_KEY"`                       // Path to key, if empty, plain HTTP will be used
		RequestPath   string `yaml:"request_path" envconfig:"CORE_REQUEST_PATH"`     // Request path, default is /dns-query
		Verbose       bool   `yaml:"verbose" envconfig:"CORE_VERBOSE"`               // Log all DNS queries
		SupportEDNS   bool   `yaml:"edns" envconfig:"CORE_EDNS"`                     // Use Extended DNS options like EDNS0-Client-Subnet
		StripESNIKey  bool   `yaml:"strip_esni" envconfig:"CORE_STRIP_ESNI"`         // Drop ESNI Key requests
	} `yaml:"core"`
	Upstream struct {
		Host          string        `yaml:"host" envconfig:"UPSTREAM_HOST"`                     // 1.1.1.1:53
		TimeOut       time.Duration `yaml:"timeout" envconfig:"UPSTREAM_TIMEOUT"`               // Timout value like: 15s, 15m, 15h, ...
		Protocol      string        `yaml:"protocol" envconfig:"UPSTREAM_PROTOCOL"`             // DNS or DOT, defaults to DNS
		AllowInsecure bool          `yaml:"allow_insecure" envconfig:"UPSTREAM_ALLOW_INSECURE"` // skip TLS certificate check (only for DOT)
	} `yaml:"upstream"`
}

func readConfigFile(cfg *Configuration, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		return err
	}

	// Fallback for the request path variable
	if cfg.Core.RequestPath == "" {
		cfg.Core.RequestPath = "/dns-query"
	}

	// Fallback for the upstream protocol variable
	if cfg.Upstream.Protocol == "" {
		cfg.Upstream.Protocol = "DNS"
	}

	return nil
}

func readConfigEnv(cfg *Configuration) error {
	err := envconfig.Process("", cfg)
	if err != nil {
		return err
	}

	return nil
}

// LoadCustomConfiguration loads a configuration file from a custom location
func LoadCustomConfiguration(filename string) (*Configuration, error) {
	// Load configuration
	var cfg Configuration

	err := readConfigFile(&cfg, filename)
	if err != nil {

		return nil, err
	}

	// Override config with environment variables
	err = readConfigEnv(&cfg)
	if err != nil {
		log.Error("Configuration env parsing failed: ", err)
		return nil, err
	}

	return &cfg, nil
}
