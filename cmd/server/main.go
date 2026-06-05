// CipherRelay Server — Public webhook relay with E2EE.
//
// The server listens for incoming webhooks on /hook/{tunnelID},
// encrypts them using the connected client's RSA public key,
// and forwards them over WebSocket.
//
// Usage:
//
//	go run ./cmd/server [-addr :8080] [-base-url http://localhost:8080]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/0xZKc0de/cipherrelay/server"
)

// getEnv returns the environment variable value or a default.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	// CLI Flags with Env Var fallbacks
	addr := flag.String("addr", getEnv("CR_ADDR", ":8080"), "server listen address")
	baseURL := flag.String("base-url", getEnv("CR_BASE_URL", "http://localhost:8080"), "public base URL for webhook endpoints")
	authTokensStr := flag.String("auth-tokens", getEnv("CR_AUTH_TOKENS", ""), "comma-separated list of valid auth tokens (empty = auth disabled)")
	certFile := flag.String("cert", getEnv("CR_CERT", ""), "TLS certificate file path")
	keyFile := flag.String("key", getEnv("CR_KEY", ""), "TLS key file path")
	flag.Parse()

	// Setup structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Parse auth tokens
	var validTokens map[string]bool
	if *authTokensStr != "" {
		validTokens = make(map[string]bool)
		for _, token := range strings.Split(*authTokensStr, ",") {
			trimmed := strings.TrimSpace(token)
			if trimmed != "" {
				validTokens[trimmed] = true
			}
		}
		logger.Info("authentication enabled", "valid_tokens_count", len(validTokens))
	} else {
		logger.Warn("authentication disabled (CR_AUTH_TOKENS not set). anyone can connect!")
	}

	hub := server.NewHub(logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", server.HandleWebSocket(hub, *baseURL, validTokens, logger))
	mux.HandleFunc("/hook/", server.HandleWebhook(hub, logger))

	// Health check endpoint.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	})

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("CipherRelay server starting", "addr", *addr, "base_url", *baseURL)
		
		var err error
		if *certFile != "" && *keyFile != "" {
			logger.Info("TLS enabled")
			err = srv.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			logger.Warn("TLS disabled (running in plaintext)")
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			logger.Error("listen error", "err", err)
			os.Exit(1)
		}
	}()

	<-shutdown
	logger.Info("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("forced shutdown", "err", err)
		os.Exit(1)
	}

	logger.Info("stopped")
}
