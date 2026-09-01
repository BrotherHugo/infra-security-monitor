package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/BrotherHugo/infra-security-monitor/internal/app"
	"github.com/BrotherHugo/infra-security-monitor/internal/version"
)

const (
	defaultConfigPath = "/etc/ism/config.yaml"
	defaultDBPath     = "/var/lib/ism/ism.db"
)

func main() {
	configPath := flag.String("config", defaultConfigPath, "path to YAML config file")
	dbPath := flag.String("db", defaultDBPath, "path to SQLite database file")
	once := flag.Bool("once", false, "run one report cycle and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	if extra := flag.Args(); len(extra) > 0 {
		slog.Error(
			"unknown arguments; use --config and --db",
			"args", extra,
			"hint", "ismd --config /etc/ism/config.yaml --db /var/lib/ism/ism.db",
		)
		os.Exit(1)
	}

	ctx := context.Background()
	opts := app.Options{
		ConfigPath: *configPath,
		DBPath:     *dbPath,
		Once:       *once,
	}

	if err := app.Run(ctx, opts); err != nil {
		slog.Error("ismd exited with error", "err", err)
		os.Exit(1)
	}
}
