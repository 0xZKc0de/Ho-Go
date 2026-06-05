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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xZKc0de/cipherrelay/internal/crypto"
	"github.com/0xZKc0de/cipherrelay/internal/models"
	"github.com/gorilla/websocket"
)

func main() {
	serverURL := flag.String("server", "ws://localhost:8080/ws", "CipherRelay server WebSocket URL")
	forwardURL := flag.String("forward", "http://localhost:3000", "local target URL to forward decrypted webhooks to")
	flag.Parse()

	// Step 1: Generate RSA-2048 key pair.
	log.Println("[client] generating RSA-2048 key pair...")
	privateKey, pubKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		log.Fatalf("[client] key generation failed: %v", err)
	}
	log.Println("[client] key pair generated successfully")

	// Step 2: Connect to the server via WebSocket.
	log.Printf("[client] connecting to %s...", *serverURL)
	conn, _, err := websocket.DefaultDialer.Dial(*serverURL, nil)
	if err != nil {
		log.Fatalf("[client] WebSocket connection failed: %v", err)
	}
	defer conn.Close()
	log.Println("[client] connected to server")

	// Step 3: Send public key for tunnel registration.
	reg := models.ClientRegistration{
		PublicKeyPEM: string(pubKeyPEM),
	}
	regJSON, err := json.Marshal(reg)
	if err != nil {
		log.Fatalf("[client] marshal registration: %v", err)
	}

	if err := conn.WriteMessage(websocket.TextMessage, regJSON); err != nil {
		log.Fatalf("[client] send registration: %v", err)
	}

	// Step 4: Receive registration response (tunnel ID + webhook URL).
	_, respMsg, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("[client] read registration response: %v", err)
	}

	var resp models.RegistrationResponse
	if err := json.Unmarshal(respMsg, &resp); err != nil {
		log.Fatalf("[client] parse registration response: %v", err)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   CipherRelay Tunnel Active                 ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Tunnel ID:   %s\n", resp.TunnelID)
	fmt.Printf("║  Webhook URL: %s\n", resp.WebhookURL)
	fmt.Printf("║  Forwarding:  %s\n", *forwardURL)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Encryption:  RSA-2048 + AES-256-GCM (Hybrid E2EE)         ║")
	fmt.Println("║  Status:      Listening for encrypted payloads...           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// HTTP client for forwarding decrypted webhooks.
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Graceful shutdown.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	// Step 5: Listen for encrypted payloads in a goroutine.
	go func() {
		defer close(done)

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("[client] WebSocket error: %v", err)
				}
				return
			}

			// Parse the encrypted payload.
			var encPayload models.EncryptedPayload
			if err := json.Unmarshal(msg, &encPayload); err != nil {
				log.Printf("[client] invalid encrypted payload: %v", err)
				continue
			}

			// Decrypt the payload using our RSA private key.
			plaintext, err := crypto.DecryptPayload(privateKey, &encPayload)
			if err != nil {
				log.Printf("[client] decryption failed: %v", err)
				continue
			}

			// Deserialize the original webhook data.
			var webhookData models.WebhookData
			if err := json.Unmarshal(plaintext, &webhookData); err != nil {
				log.Printf("[client] invalid webhook data: %v", err)
				continue
			}

			log.Printf("[client] ← received %s webhook (%d bytes)", webhookData.Method, len(webhookData.Body))

			// Forward the decrypted webhook to the local service.
			go forwardWebhook(httpClient, *forwardURL, &webhookData)
		}
	}()

	// Wait for shutdown signal or connection close.
	select {
	case <-shutdown:
		log.Println("[client] shutting down...")
		conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
	case <-done:
		log.Println("[client] connection closed by server")
	}
}

// forwardWebhook sends the decrypted webhook data as an HTTP request
// to the local target service, preserving the original method, headers, and body.
func forwardWebhook(client *http.Client, targetURL string, data *models.WebhookData) {
	req, err := http.NewRequest(data.Method, targetURL, bytes.NewReader(data.Body))
	if err != nil {
		log.Printf("[forward] create request error: %v", err)
		return
	}

	// Restore original headers.
	for key, values := range data.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[forward] request error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read and discard the response body.
	body, _ := io.ReadAll(resp.Body)

	log.Printf("[forward] → %s %s → %d (%d bytes response)",
		data.Method, targetURL, resp.StatusCode, len(body))
}
