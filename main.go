package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"singbox-client/internal/api"
	"singbox-client/internal/bypass"
	"singbox-client/internal/config"
	"singbox-client/internal/singbox"
	"singbox-client/internal/subscription"
)

//go:embed web/templates/* web/static/*
var webFS embed.FS

// Timeouts
const (
	ServerReadTimeout  = 15 * time.Second
	ServerWriteTimeout = 15 * time.Second
	ShutdownTimeout    = 10 * time.Second
)

func main() {
	// Determine data directory
	dataDir := os.Getenv("SINGBOX_DATA_DIR")
	if dataDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		dataDir = filepath.Join(homeDir, ".singbox-client")
	}

	// Initialize configuration
	cfgMgr := config.GetManager()
	if err := cfgMgr.Initialize(dataDir); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	cfg := cfgMgr.GetConfig()

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize subscription updater
	updater := subscription.GetUpdater()
	if err := updater.Initialize(dataDir); err != nil {
		log.Fatalf("Failed to initialize subscription updater: %v", err)
	}

	// Start auto-update if enabled
	if cfg.Subscription.AutoUpdate {
		interval := time.Duration(cfg.Subscription.UpdateInterval) * time.Minute
		updater.StartAutoUpdate(interval)
	}

	// Initialize process manager
	processMgr := singbox.GetProcessManager()
	processMgr.Initialize(cfg.SingBox.BinaryPath, cfg.SingBox.ConfigPath)

	// Initialize bypass manager
	bypassMgr := bypass.GetManager()
	if err := bypassMgr.Initialize(cfgMgr); err != nil {
		log.Printf("Warning: failed to initialize bypass manager: %v", err)
	} else {
		// Apply bypass routes
		if err := bypassMgr.ApplyBypassRoutes(); err != nil {
			log.Printf("Warning: failed to apply bypass routes: %v", err)
		}
		// Start auto-refresh every hour
		bypassMgr.StartAutoRefresh(1 * time.Hour)
	}

	// Auto-start sing-box if enabled
	state := cfgMgr.GetState()
	if state.AutoStart {
		log.Println("Auto-starting sing-box...")
		generator := singbox.NewConfigGenerator(cfgMgr.GetDataDir())
		nodes := updater.GetNodes()
		if len(nodes) > 0 {
			sbConfig, err := generator.Generate(nodes, cfg, state)
			if err != nil {
				log.Printf("Warning: failed to generate config for auto-start: %v", err)
			} else if err := generator.SaveConfig(sbConfig, cfg.SingBox.ConfigPath); err != nil {
				log.Printf("Warning: failed to save config for auto-start: %v", err)
			} else if err := processMgr.Start(); err != nil {
				log.Printf("Warning: failed to auto-start sing-box: %v", err)
			} else {
				log.Println("sing-box auto-started successfully")
			}
		} else {
			log.Println("No nodes available, skipping auto-start")
		}
	}

	// Create router
	router := api.NewRouter(webFS)

	// Create server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  ServerReadTimeout,
		WriteTimeout: ServerWriteTimeout,
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")

		// Stop auto-update
		updater.StopAutoUpdate()

		// Stop sing-box if running
		if processMgr.GetState() == singbox.StateRunning {
			if err := processMgr.Stop(); err != nil {
				log.Printf("Warning: failed to stop sing-box: %v", err)
			}
		}

		// Stop bypass auto-refresh
		bypassMgr.StopAutoRefresh()

		// Remove bypass routes
		if err := bypassMgr.RemoveBypassRoutes(); err != nil {
			log.Printf("Warning: failed to remove bypass routes: %v", err)
		}

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Warning: server shutdown error: %v", err)
			server.Close()
		}
	}()

	// Start server
	log.Printf("SingBox Manager starting on http://%s", addr)
	log.Printf("Data directory: %s", dataDir)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped")
}

// validateConfig validates the configuration
func validateConfig(cfg config.Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	if cfg.SingBox.BinaryPath == "" {
		return fmt.Errorf("sing-box binary path is required")
	}

	if cfg.SingBox.ConfigPath == "" {
		return fmt.Errorf("sing-box config path is required")
	}

	if len(cfg.DNS.DomesticServers) == 0 {
		return fmt.Errorf("at least one domestic DNS server is required")
	}

	if len(cfg.DNS.ProxyServers) == 0 {
		return fmt.Errorf("at least one proxy DNS server is required")
	}

	return nil
}
