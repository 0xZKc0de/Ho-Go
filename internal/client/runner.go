package client

import (
	"encoding/json"
	"fmt"
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

// Config holds the configuration for the CipherRelay client.
type Config struct {
	ServerURL   string
	ForwardURL  string
	AuthToken   string
	RequestedID string
}

// Run starts the client lifecycle: generates keys, connects to the server,
// registers the tunnel, and starts the decryption/forwarding loop.
func Run(cfg Config) error {
	// Step 1: Generate RSA-2048 key pair.
	log.Println("[client] generating RSA-2048 key pair...")
	privateKey, pubKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	log.Println("[client] key pair generated successfully")

	// Step 2: Connect to the server via WebSocket.
	log.Printf("[client] connecting to %s...", cfg.ServerURL)
	conn, _, err := websocket.DefaultDialer.Dial(cfg.ServerURL, nil)
	if err != nil {
		return fmt.Errorf("WebSocket connection failed: %w", err)
	}
	defer conn.Close()
	log.Println("[client] connected to server")

	// Step 3: Send public key and optional configs for tunnel registration.
	reg := models.ClientRegistration{
		PublicKeyPEM: string(pubKeyPEM),
		AuthToken:    cfg.AuthToken,
		RequestedID:  cfg.RequestedID,
	}
	regJSON, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal registration: %w", err)
	}

	if err := conn.WriteMessage(websocket.TextMessage, regJSON); err != nil {
		return fmt.Errorf("send registration: %w", err)
	}

	// Step 4: Receive registration response (tunnel ID + webhook URL).
	_, respMsg, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read registration response: %w", err)
	}

	// Check if server rejected us with a close message (e.g., bad auth, ID taken)
	if err == nil && len(respMsg) == 0 {
		return fmt.Errorf("server closed connection (check auth token or requested ID)")
	}

	var resp models.RegistrationResponse
	if err := json.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("parse registration response: %w (msg: %s)", err, string(respMsg))
	}

	PrintBanner(resp.TunnelID, resp.WebhookURL, cfg.ForwardURL)

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
			go ForwardWebhook(httpClient, cfg.ForwardURL, &webhookData)
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

	return nil
}
