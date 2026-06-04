package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/danangamw/go-janitor/internal/cleaner"
	"github.com/danangamw/go-janitor/internal/config"
	"github.com/danangamw/go-janitor/internal/reporter"
	"github.com/danangamw/go-janitor/internal/runtime"
	"github.com/danangamw/go-janitor/internal/scanner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	// Fallback: read module info embedded by `go install` when ldflags are not set.
	if version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		version = v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				commit = s.Value[:7]
			} else {
				commit = s.Value
			}
		case "vcs.time":
			date = s.Value
		}
	}
}

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	var cfgFile string

	root := &cobra.Command{
		Use:   "go-janitor",
		Short: "Docker maintenance & security audit CLI",
		Long:  "go-janitor cleans up Docker garbage and audits running containers for CVEs.",
	}

	// Persistent flags (available to all sub-commands)
	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "path to YAML config file")
	pf.Bool("dry-run", false, "simulate without executing")
	pf.Duration("max-age", 48*time.Hour, "max age of stopped containers before removal")
	pf.String("severity", "CRITICAL,HIGH", "Trivy severity threshold")
	pf.Int("concurrency", 5, "max parallel scan goroutines")
	pf.String("output", "text", "output format: text or json")
	pf.String("output-file", "", "path for JSON report export")
	pf.String("webhook", "", "Slack/Discord webhook URL")
	pf.String("engine", "docker", "container engine to use: docker, podman, auto")
	pf.String("socket", "/var/run/docker.sock", "Docker Unix socket path")
	pf.String("log-level", "info", "log level: debug, info, warn, error")

	// Bind each flag explicitly with the underscore key that mapstructure expects.
	_ = viper.BindPFlag("dry_run", pf.Lookup("dry-run"))
	_ = viper.BindPFlag("max_age", pf.Lookup("max-age"))
	_ = viper.BindPFlag("severity", pf.Lookup("severity"))
	_ = viper.BindPFlag("concurrency", pf.Lookup("concurrency"))
	_ = viper.BindPFlag("output", pf.Lookup("output"))
	_ = viper.BindPFlag("output_file", pf.Lookup("output-file"))
	_ = viper.BindPFlag("webhook", pf.Lookup("webhook"))
	_ = viper.BindPFlag("engine", pf.Lookup("engine"))
	_ = viper.BindPFlag("socket", pf.Lookup("socket"))
	_ = viper.BindPFlag("log_level", pf.Lookup("log-level"))

	root.AddCommand(
		buildCleanCmd(&cfgFile),
		buildScanCmd(&cfgFile),
		buildRunCmd(&cfgFile),
		buildVersionCmd(),
	)

	return root
}

func loadConfig(cfgFile string) (*config.Config, error) {
	// Re-bind all viper values from already-parsed pflags
	_ = viper.BindEnv("dry_run", "JANITOR_DRY_RUN")
	return config.Load(cfgFile)
}

// runWithContext returns a root context that cancels on SIGINT/SIGTERM.
func runWithContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// exitCode derives the process exit code from the operation results.
// 0 = success, 1 = total failure, 2 = partial failure.
func exitCode(cleanErr, scanErr error, scanStats reporter.ScannerStats) int {
	if cleanErr != nil && scanErr != nil {
		return 1
	}
	if cleanErr != nil || scanErr != nil || scanStats.ScanErrors > 0 {
		return 2
	}
	return 0
}

// ---- clean command ----

func buildCleanCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Run Docker Trash Collector",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(*cfgFile)
			if err != nil {
				return err
			}
			reporter.InitLogger(cfg.LogLevel, cfg.Output)

			ctx, stop := runWithContext()
			defer stop()

			cli, err := initRuntime(cfg)
			if err != nil {
				return err
			}
			defer cli.Close()

			stats := cleaner.Run(ctx, cli, cfg.MaxAge, cfg.DryRun)

			if strings.ToLower(cfg.Output) == "text" {
				reporter.PrintCleanerSummary(version, stats, cfg.MaxAge, cfg.DryRun)
			}

			if cfg.OutputFile != "" {
				r := &reporter.Report{
					RunID:     newRunID(),
					StartedAt: time.Now(),
					Cleaner:   stats,
				}
				if err := reporter.WriteJSON(cfg.OutputFile, r); err != nil {
					slog.Warn("failed to write report", "error", err)
				}
			}

			if errors.Is(ctx.Err(), context.Canceled) {
				slog.Info("shutdown requested, in-progress operations completed")
			}
			return nil
		},
	}
}

// ---- scan command ----

func buildScanCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run Security Auditor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(*cfgFile)
			if err != nil {
				return err
			}
			reporter.InitLogger(cfg.LogLevel, cfg.Output)

			ctx, stop := runWithContext()
			defer stop()

			cli, err := initRuntime(cfg)
			if err != nil {
				return err
			}
			defer cli.Close()

			startedAt := time.Now()
			scanStats, results := scanner.Run(ctx, cli, cfg.Severity, cfg.Concurrency)

			if strings.ToLower(cfg.Output) == "text" {
				var rows []reporter.ScanRow
				for _, r := range results {
					hasCritical := false
					hasHigh := false
					for _, v := range r.Vulnerabilities {
						if v.Severity == "CRITICAL" {
							hasCritical = true
						}
						if v.Severity == "HIGH" {
							hasHigh = true
						}
					}
					rows = append(rows, reporter.ScanRow{
						ImageID:     r.ImageID,
						Vulns:       len(r.Vulnerabilities),
						HasCritical: hasCritical,
						HasHigh:     hasHigh,
						DurationMs:  r.ScanDuration.Milliseconds(),
						Error:       r.Error,
					})
				}
				reporter.PrintScanTable(version, rows, scanStats, cfg.Severity, cfg.Concurrency)
			}

			if cfg.Webhook != "" && (scanStats.ImagesWithCritical > 0 || scanStats.ImagesWithHigh > 0) {
				host, _ := os.Hostname()
				reporter.SendAlert(ctx, cfg.Webhook, scanStats, host, startedAt)
			}

			if cfg.OutputFile != "" {
				r := &reporter.Report{
					RunID:           newRunID(),
					StartedAt:       startedAt,
					DurationSeconds: time.Since(startedAt).Seconds(),
					Scanner:         scanStats,
				}
				if err := reporter.WriteJSON(cfg.OutputFile, r); err != nil {
					slog.Warn("failed to write report", "error", err)
				}
			}

			code := exitCode(nil, nil, scanStats)
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}

// ---- run command (default: clean + scan) ----

func buildRunCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run Trash Collector then Security Auditor (default)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(*cfgFile)
			if err != nil {
				return err
			}
			reporter.InitLogger(cfg.LogLevel, cfg.Output)

			ctx, stop := runWithContext()
			defer stop()

			cli, err := initRuntime(cfg)
			if err != nil {
				return err
			}
			defer cli.Close()

			startedAt := time.Now()
			runID := newRunID()

			cleanStats := cleaner.Run(ctx, cli, cfg.MaxAge, cfg.DryRun)
			scanStats, results := scanner.Run(ctx, cli, cfg.Severity, cfg.Concurrency)

			if strings.ToLower(cfg.Output) == "text" {
				reporter.PrintCleanerSummary(version, cleanStats, cfg.MaxAge, cfg.DryRun)

				var rows []reporter.ScanRow
				for _, r := range results {
					hasCritical := false
					hasHigh := false
					for _, v := range r.Vulnerabilities {
						if v.Severity == "CRITICAL" {
							hasCritical = true
						}
						if v.Severity == "HIGH" {
							hasHigh = true
						}
					}
					rows = append(rows, reporter.ScanRow{
						ImageID:     r.ImageID,
						Vulns:       len(r.Vulnerabilities),
						HasCritical: hasCritical,
						HasHigh:     hasHigh,
						DurationMs:  r.ScanDuration.Milliseconds(),
						Error:       r.Error,
					})
				}
				reporter.PrintScanTable(version, rows, scanStats, cfg.Severity, cfg.Concurrency)
			}

			if cfg.Webhook != "" && (scanStats.ImagesWithCritical > 0 || scanStats.ImagesWithHigh > 0) {
				host, _ := os.Hostname()
				reporter.SendAlert(ctx, cfg.Webhook, scanStats, host, startedAt)
			}

			if cfg.OutputFile != "" {
				r := &reporter.Report{
					RunID:           runID,
					StartedAt:       startedAt,
					DurationSeconds: time.Since(startedAt).Seconds(),
					Cleaner:         cleanStats,
					Scanner:         scanStats,
				}
				if err := reporter.WriteJSON(cfg.OutputFile, r); err != nil {
					slog.Warn("failed to write report", "error", err)
				}
			}

			if errors.Is(ctx.Err(), context.Canceled) {
				slog.Info("shutdown requested, in-progress operations completed")
			}

			code := exitCode(nil, nil, scanStats)
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}

// ---- version command ----

func buildVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("go-janitor %s\n", version)
		},
	}
}

func newRunID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		return "unknown"
	}
	return id.String()
}

func initRuntime(cfg *config.Config) (runtime.ContainerRuntime, error) {
	engine := strings.ToLower(cfg.Engine)
	socket := cfg.Socket

	if engine == "auto" {
		socketsToTry := []string{
			"/var/run/docker.sock",
			getPodmanRootlessSocket(),
			"/run/podman/podman.sock",
		}

		for _, s := range socketsToTry {
			if s == "" {
				continue
			}
			if _, err := os.Stat(s); err == nil {
				rt, err := runtime.NewDockerRuntime(s)
				if err == nil {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					pingErr := rt.Ping(ctx)
					cancel()
					if pingErr == nil {
						slog.Info("auto-detected container engine", "socket", s)
						return rt, nil
					}
					rt.Close()
				}
			}
		}

		return nil, fmt.Errorf("could not auto-detect container engine socket (tried docker/podman sockets)")
	}

	if engine == "podman" && (socket == "/var/run/docker.sock" || socket == "") {
		slog.Info("podman engine selected, trying to auto-detect podman socket")
		rootless := getPodmanRootlessSocket()

		found := false
		if rootless != "" {
			if _, err := os.Stat(rootless); err == nil {
				socket = rootless
				found = true
			}
		}
		if !found {
			if _, err := os.Stat("/run/podman/podman.sock"); err == nil {
				socket = "/run/podman/podman.sock"
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf(
				"podman socket not found (tried %s and /run/podman/podman.sock)\n"+
					"  hint: enable it with: systemctl --user start podman.socket",
				rootless,
			)
		}
	}

	slog.Info("connecting to container engine", "engine", engine, "socket", socket)
	rt, err := runtime.NewDockerRuntime(socket)
	if err != nil {
		return nil, err
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Ping(ctx); err != nil {
		rt.Close()
		return nil, err
	}

	return rt, nil
}

func getPodmanRootlessSocket() string {
	uid := os.Getuid()
	if uid == 0 {
		return ""
	}
	return fmt.Sprintf("/run/user/%d/podman/podman.sock", uid)
}
