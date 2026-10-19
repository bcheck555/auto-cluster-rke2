package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	manage := flag.Bool("manage", false, "root-only membership operation: bounded JSON on stdin; public status on stdout")
	restrict := flag.Bool("restrict", false, "root-only fail-closed control recovery for systemd shutdown")
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
	if *restrict {
		if os.Geteuid() != 0 || *manage || *health || *once || *check {
			return 2
		}
		attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if formation.Restrict(attempt, s) != nil {
			return 1
		}
		return 0
	}
	if *manage {
		if os.Geteuid() != 0 || *health || *once || *check {
			return 2
		}
		var request formation.ManagementRequest
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16385))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			return 2
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return 2
		}
		attempt, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		status, err := formation.Manage(attempt, s, request)
		if err != nil {
			fmt.Fprintln(os.Stderr, "host-agent: membership operation blocked:", err)
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(status) != nil {
			return 1
		}
		return 0
	}
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
		var healing formation.HealingBlocked
		if err == nil {
			fmt.Fprintln(os.Stdout, "host-agent: healthy")
		} else if errors.As(err, &healing) {
			fmt.Fprintln(os.Stderr, "host-agent:", healing)
		} else if formation.Permanent(err) {
			fmt.Fprintln(os.Stderr, "host-agent: reconciliation required; convergence stopped:", err)
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
