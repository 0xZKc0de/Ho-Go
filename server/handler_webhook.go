package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/0xZKc0de/cipherrelay/internal/crypto"
	"github.com/0xZKc0de/cipherrelay/internal/models"
)

// HandleWebhook returns an HTTP handler that accepts incoming webhook
// requests for a specific tunnel ID. It reads the full request (method,
// headers, body), encrypts it using the client's RSA public key via
// hybrid encryption, and forwards the encrypted payload over WebSocket.
func HandleWebhook(hub *Hub, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract tunnel ID from URL path: /hook/{tunnelID}
		tunnelID := strings.TrimPrefix(r.URL.Path, "/hook/")
		if tunnelID == "" {
			http.Error(w, `{"error":"missing tunnel ID"}`, http.StatusBadRequest)
			return
		}

		// Look up the registered client.
		client := hub.GetClient(tunnelID)
		if client == nil {
			http.Error(w, `{"error":"tunnel not found"}`, http.StatusNotFound)
			return
		}

		// Read the webhook body with a 10MB limit.
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"payload too large or failed to read body"}`, http.StatusRequestEntityTooLarge)
			return
		}
		defer r.Body.Close()

		// Build the WebhookData from the incoming request.
		webhookData := models.WebhookData{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header,
			Body:    body,
		}

		// Serialize the webhook data to JSON for encryption.
		plaintext, err := json.Marshal(webhookData)
		if err != nil {
			logger.Error("failed to serialize webhook data", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		// Encrypt using hybrid encryption (RSA + AES-GCM).
		encPayload, err := crypto.EncryptPayload(client.PublicKey, plaintext)
		if err != nil {
			logger.Error("encryption error", "tunnel_id", tunnelID, "err", err)
			http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
			return
		}

		// Serialize the encrypted payload and send it to the client.
		encJSON, err := json.Marshal(encPayload)
		if err != nil {
			logger.Error("failed to serialize encrypted payload", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		// Non-blocking send to avoid blocking the webhook response.
		select {
		case client.Send <- encJSON:
			logger.Info("forwarded encrypted payload", "tunnel_id", tunnelID, "bytes", len(body))
		default:
			logger.Warn("send buffer full, dropping payload", "tunnel_id", tunnelID)
			http.Error(w, `{"error":"tunnel send buffer full"}`, http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"forwarded","tunnel_id":"%s"}`, tunnelID)
	}
}
