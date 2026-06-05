// CipherRelay Client — Local webhook receiver with E2EE decryption.
//
// The client generates an RSA-2048 key pair, connects to the CipherRelay
// server via WebSocket, receives encrypted webhook payloads, decrypts
// them locally, and forwards the original HTTP request to a local service.
//
// Usage:
//
//	go run ./cmd/client [-server ws://localhost:8080/ws] [-forward http://localhost:3000]
package main

import (
	"flag"
	"log"
	"os"

	"github.com/0xZKc0de/cipherrelay/internal/client"
)

// getEnv returns the environment variable value or a default.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	serverURL := flag.String("server", getEnv("CR_SERVER", "ws://localhost:8080/ws"), "CipherRelay server WebSocket URL")
	forwardURL := flag.String("forward", getEnv("CR_FORWARD", "http://localhost:3000"), "local target URL to forward decrypted webhooks to")
	authToken := flag.String("auth-token", getEnv("CR_AUTH_TOKEN", ""), "authentication token if required by server")
	requestedID := flag.String("id", getEnv("CR_TUNNEL_ID", ""), "request a specific static tunnel ID (e.g. 'my-dev-env')")
	flag.Parse()

	cfg := client.Config{
		ServerURL:   *serverURL,
		ForwardURL:  *forwardURL,
		AuthToken:   *authToken,
		RequestedID: *requestedID,
	}

	if err := client.Run(cfg); err != nil {
		log.Fatalf("[client] fatal error: %v", err)
	}
}
