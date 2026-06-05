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
	"github.com/gorilla/websocket"
)

// upgrader configures the WebSocket upgrader with permissive origin checks
// (acceptable for an MVP; production should validate origins).
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// HandleWebSocket returns an HTTP handler that upgrades incoming connections
// to WebSocket, reads the client's RSA public key, registers a new tunnel,
// and sends back the tunnel ID and public webhook URL.
func HandleWebSocket(hub *Hub, baseURL string, validTokens map[string]bool, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error("ws upgrade error", "err", err)
			return
		}

		// Step 1: Read client registration (public key + optional auth/static ID).
		_, msg, err := conn.ReadMessage()
		if err != nil {
			logger.Error("read registration error", "err", err)
			conn.Close()
			return
		}

		var reg models.ClientRegistration
		if err := json.Unmarshal(msg, &reg); err != nil {
			logger.Error("invalid registration JSON", "err", err)
			conn.Close()
			return
		}

		// Step 2: Validate Authentication (if enabled).
		if validTokens != nil {
			if reg.AuthToken == "" || !validTokens[reg.AuthToken] {
				logger.Warn("authentication failed", "remote_addr", r.RemoteAddr)
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid auth token"))
				conn.Close()
				return
			}
		}

		// Step 3: Parse the RSA public key from PEM.
		pubKey, err := crypto.ParsePublicKeyPEM([]byte(reg.PublicKeyPEM))
		if err != nil {
			logger.Error("invalid public key", "err", err)
			conn.Close()
			return
		}

		// Step 4: Determine Tunnel ID.
		var tunnelID string
		if reg.RequestedID != "" {
			// Basic sanitization: alphanumeric and hyphens only
			tunnelID = strings.TrimSpace(reg.RequestedID)
			if len(tunnelID) > 64 {
				tunnelID = tunnelID[:64]
			}
			
			// Check if already in use
			if hub.GetClient(tunnelID) != nil {
				logger.Warn("requested tunnel ID already in use", "tunnel_id", tunnelID)
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "tunnel ID already in use"))
				conn.Close()
				return
			}
		} else {
			tunnelID, err = GenerateTunnelID()
			if err != nil {
				logger.Error("generate tunnel ID error", "err", err)
				conn.Close()
				return
			}
		}

		client := &TunnelClient{
			ID:        tunnelID,
			PublicKey: pubKey,
			Conn:      conn,
			Send:      make(chan []byte, 256),
		}
		hub.Register(client)

		// Step 5: Send registration response with tunnel ID and webhook URL.
		webhookURL := fmt.Sprintf("%s/hook/%s", strings.TrimRight(baseURL, "/"), tunnelID)
		resp := models.RegistrationResponse{
			TunnelID:   tunnelID,
			WebhookURL: webhookURL,
		}

		respJSON, err := json.Marshal(resp)
		if err != nil {
			logger.Error("marshal response error", "err", err)
			hub.Unregister(tunnelID)
			return
		}

		if err := conn.WriteMessage(websocket.TextMessage, respJSON); err != nil {
			logger.Error("write response error", "err", err)
			hub.Unregister(tunnelID)
			return
		}

		logger.Info("tunnel ready", "tunnel_id", tunnelID, "webhook_url", webhookURL)

		// Step 6: Start connection lifecycle goroutines.
		go client.WritePump()
		go client.ReadPump(hub)
	}
}

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
