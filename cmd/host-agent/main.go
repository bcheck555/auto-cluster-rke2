package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auto-cluster-rke2/internal/formation"
)

func main() { os.Exit(run()) }
func run() int {
	config := flag.String("config", "/etc/autonomous-rke2/node.json", "common image configuration")
	once := flag.Bool("once", false, "perform one bounded convergence attempt")
	check := flag.Bool("check", false, "validate common configuration without creating state")
	health := flag.Bool("health", false, "independently verify local cluster health and emit public evidence")
	flag.Parse()
	if flag.NArg() != 0 {
		return 2
	}
	s, err := formation.LoadSettings(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "host-agent: invalid common configuration")
		return 2
	}
	if *check {
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *health {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		evidence, err := formation.CheckHealth(attempt, s)
		if err != nil {
			fmt.Fprintln(os.Stderr, "host-agent: independent health check failed")
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(evidence) != nil {
			return 1
		}
		return 0
	}
	err = formation.Run(ctx, s, *once, func(err error) {
		if err == nil {
			fmt.Fprintln(os.Stdout, "host-agent: healthy")
		} else if formation.Permanent(err) {
			fmt.Fprintln(os.Stderr, "host-agent: reconciliation required; convergence stopped")
		} else {
			fmt.Fprintln(os.Stderr, "host-agent: waiting for cluster or local prerequisites")
		}
	})
	if ctx.Err() != nil || err == nil {
		return 0
	}
	if formation.Permanent(err) {
		return 2
	}
	return 1
}
