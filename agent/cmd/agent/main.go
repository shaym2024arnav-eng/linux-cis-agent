package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"linux-cis-agent/agent/internal/cis"
	"linux-cis-agent/agent/internal/collector"
	"linux-cis-agent/agent/internal/hostinfo"
	"linux-cis-agent/agent/internal/sender"
)

const version = "0.1.0"

type Config struct {
	APIURL string `json:"api_url"`
	APIKey string `json:"api_key"`
}

type Payload struct {
	AgentVersion string              `json:"agent_version"`
	Host         hostinfo.HostInfo   `json:"host"`
	Packages     []collector.Package `json:"packages"`
	CISResults   []cis.Result        `json:"cis_results"`
}

func main() {
	cfgPath := flag.String("config", "/etc/cis-agent/agent.json", "path to config file")
	dryRun := flag.Bool("dry-run", false, "print the payload instead of sending it")
	flag.Parse()

	host, err := hostinfo.Collect()
	if err != nil {
		log.Fatalf("collect host info: %v", err)
	}
	pkgs, err := collector.Collect()
	if err != nil {
		log.Printf("package collection failed, continuing: %v", err)
	}
	p := Payload{AgentVersion: version, Host: host, Packages: pkgs, CISResults: cis.RunAll()}

	if *dryRun {
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := sender.Send(cfg.APIURL+"/ingest", cfg.APIKey, p); err != nil {
		log.Fatalf("send: %v", err)
	}
	log.Printf("sent %d packages and %d CIS results for %s", len(pkgs), len(p.CISResults), host.Hostname)
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if c.APIURL == "" || c.APIKey == "" {
		return c, fmt.Errorf("api_url and api_key must be set in %s", path)
	}
	return c, nil
}
