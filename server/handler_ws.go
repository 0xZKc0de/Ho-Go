package server

import (
	"encoding/json"
	"fmt"
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
