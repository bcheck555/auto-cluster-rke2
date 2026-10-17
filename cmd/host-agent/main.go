package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"autonomous-rke2/internal/bootstrap"
	"autonomous-rke2/internal/durable"
	"autonomous-rke2/internal/hostagent"
	"autonomous-rke2/internal/identity"
	"autonomous-rke2/internal/state"
)

func main() { os.Exit(run()) }
func run() int {
	config := flag.String("config", "/etc/autonomous-rke2/host.json", "private host configuration")
	once := flag.Bool("once", false, "perform one bounded convergence attempt")
	enroll := flag.Bool("enroll", false, "create/load identity and emit public enrollment only")
	identityDirectory := flag.String("identity-directory", "", "identity path for enrollment before configuration is provisioned")
	check := flag.Bool("check", false, "validate local prerequisites without requesting grants or starting services")
	health := flag.Bool("health", false, "emit read-only observed cluster/node/etcd health evidence")
	flag.Parse()
	if flag.NArg() != 0 || (*identityDirectory != "" && !*enroll) || (*check && *enroll) || (*health && (*check || *enroll)) {
		fmt.Fprintln(os.Stderr, "host-agent: invalid arguments")
		return 2
	}
	if *enroll && *identityDirectory != "" {
		if !filepath.IsAbs(*identityDirectory) || filepath.Clean(*identityDirectory) != *identityDirectory {
			return 2
		}
		parent := hostagent.Settings{StateDirectory: filepath.Dir(*identityDirectory)}
		if err := parent.PrepareState(); err != nil {
			return 2
		}
		id, err := hostagent.Enroll(context.Background(), identity.NewFileStore(*identityDirectory))
		if err != nil {
			return 2
		}
		if json.NewEncoder(os.Stdout).Encode(id) != nil {
			return 2
		}
		return 0
	}
	settings, err := hostagent.LoadSettings(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "host-agent: invalid or inaccessible configuration")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := settings.PrepareState(); err != nil {
		fmt.Fprintln(os.Stderr, "host-agent: unsafe state directory")
		return 2
	}
	if *enroll {
		id, err := hostagent.Enroll(ctx, settings.Identity())
		if err != nil {
			fmt.Fprintln(os.Stderr, "host-agent: identity unavailable")
			return 2
		}
		if json.NewEncoder(os.Stdout).Encode(id) != nil {
			return 2
		}
		return 0
	}
	if *check || *health {
		id, err := settings.Identity().LoadOrCreate(ctx)
		if err != nil {
			return 2
		}
		snapshot, err := hostagent.NewLinuxRuntime(nil).Inspect(ctx, settings.Plan, id.ID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "host-agent: prerequisite check failed")
			return 2
		}
		if *health {
			if !snapshot.ConfigMatches {
				return 2
			}
			checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			evidence, err := (&hostagent.HealthChecker{Observer: settings.Observer}).Check(checkCtx, settings.Plan, id.ID, false)
			if err != nil {
				fmt.Fprintln(os.Stderr, "host-agent: independent health check failed")
				return 1
			}
			_ = json.NewEncoder(os.Stdout).Encode(struct {
				ObservedAt        time.Time
				ClusterID, HostID string
				Evidence          hostagent.Evidence
			}{time.Now().UTC(), settings.Plan.ClusterID, id.ID, evidence})
			return 0
		}
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			HostID                          string
			Running, HasData, ConfigMatches bool
		}{id.ID, snapshot.Running, snapshot.HasData, snapshot.ConfigMatches})
		return 0
	}
	for {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := settings.Execute(attempt)
		cancel()
		if ctx.Err() != nil {
			return 0
		}
		if err == nil {
			fmt.Fprintln(os.Stdout, "host-agent: healthy")
		} else if permanent(err) {
			fmt.Fprintln(os.Stderr, "host-agent: reconciliation required; no further changes")
			return 2
		} else {
			fmt.Fprintln(os.Stderr, "host-agent: waiting for prerequisites")
		}
		if *once {
			if err != nil {
				return 1
			}
			return 0
		}
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}

func permanent(err error) bool {
	return errors.Is(err, hostagent.ErrInvalid) || errors.Is(err, hostagent.ErrReconcile) || errors.Is(err, bootstrap.ErrDenied) || errors.Is(err, bootstrap.ErrInvalid) || errors.Is(err, bootstrap.ErrTrustMismatch) || errors.Is(err, bootstrap.ErrClusterMismatch) || errors.Is(err, bootstrap.ErrExpired) || errors.Is(err, bootstrap.ErrReplay) || errors.Is(err, bootstrap.ErrGrantNotFound) || errors.Is(err, durable.ErrCorrupt) || errors.Is(err, durable.ErrUnsafe) || errors.Is(err, state.ErrConflict)
}
