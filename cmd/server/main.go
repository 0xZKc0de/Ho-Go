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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xZKc0de/cipherrelay/server"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	baseURL := flag.String("base-url", "http://localhost:8080", "public base URL for webhook endpoints")
	flag.Parse()

	hub := server.NewHub()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", server.HandleWebSocket(hub, *baseURL))
	mux.HandleFunc("/hook/", server.HandleWebhook(hub))

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
		log.Printf("[server] CipherRelay server listening on %s", *addr)
		log.Printf("[server] Webhook base URL: %s", *baseURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[server] listen error: %v", err)
		}
	}()

	<-shutdown
	log.Println("[server] shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[server] forced shutdown: %v", err)
	}

	log.Println("[server] stopped")
}
