package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
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
//
// Protocol:
//  1. Client connects via WebSocket.
//  2. Client sends a JSON ClientRegistration message with its PEM-encoded public key.
//  3. Server registers the tunnel and responds with a JSON RegistrationResponse.
//  4. Server starts read/write pumps for the connection lifecycle.
func HandleWebSocket(hub *Hub, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[ws] upgrade error: %v", err)
			return
		}

		// Step 1: Read client registration (public key).
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[ws] read registration error: %v", err)
			conn.Close()
			return
		}

		var reg models.ClientRegistration
		if err := json.Unmarshal(msg, &reg); err != nil {
			log.Printf("[ws] invalid registration JSON: %v", err)
			conn.Close()
			return
		}

		// Step 2: Parse the RSA public key from PEM.
		pubKey, err := crypto.ParsePublicKeyPEM([]byte(reg.PublicKeyPEM))
		if err != nil {
			log.Printf("[ws] invalid public key: %v", err)
			conn.Close()
			return
		}

		// Step 3: Generate tunnel ID and register the client.
		tunnelID, err := GenerateTunnelID()
		if err != nil {
			log.Printf("[ws] generate tunnel ID error: %v", err)
			conn.Close()
			return
		}

		client := &TunnelClient{
			ID:        tunnelID,
			PublicKey: pubKey,
			Conn:      conn,
			Send:      make(chan []byte, 256),
		}
		hub.Register(client)

		// Step 4: Send registration response with tunnel ID and webhook URL.
		webhookURL := fmt.Sprintf("%s/hook/%s", strings.TrimRight(baseURL, "/"), tunnelID)
		resp := models.RegistrationResponse{
			TunnelID:   tunnelID,
			WebhookURL: webhookURL,
		}

		respJSON, err := json.Marshal(resp)
		if err != nil {
			log.Printf("[ws] marshal response error: %v", err)
			hub.Unregister(tunnelID)
			return
		}

		if err := conn.WriteMessage(websocket.TextMessage, respJSON); err != nil {
			log.Printf("[ws] write response error: %v", err)
			hub.Unregister(tunnelID)
			return
		}

		log.Printf("[ws] tunnel active: %s → %s", tunnelID, webhookURL)

		// Step 5: Start connection lifecycle goroutines.
		go client.WritePump()
		go client.ReadPump(hub)
	}
}

// HandleWebhook returns an HTTP handler that accepts incoming webhook
// requests for a specific tunnel ID. It reads the full request (method,
// headers, body), encrypts it using the client's RSA public key via
// hybrid encryption, and forwards the encrypted payload over WebSocket.
//
// URL pattern: /hook/{tunnelID}
func HandleWebhook(hub *Hub) http.HandlerFunc {
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

		// Read the webhook body.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read body"}`, http.StatusInternalServerError)
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
			http.Error(w, `{"error":"failed to serialize webhook data"}`, http.StatusInternalServerError)
			return
		}

		// Encrypt using hybrid encryption (RSA + AES-GCM).
		encPayload, err := crypto.EncryptPayload(client.PublicKey, plaintext)
		if err != nil {
			log.Printf("[webhook] encryption error for tunnel %s: %v", tunnelID, err)
			http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
			return
		}

		// Serialize the encrypted payload and send it to the client.
		encJSON, err := json.Marshal(encPayload)
		if err != nil {
			http.Error(w, `{"error":"failed to serialize encrypted payload"}`, http.StatusInternalServerError)
			return
		}

		// Non-blocking send to avoid blocking the webhook response.
		select {
		case client.Send <- encJSON:
			log.Printf("[webhook] forwarded encrypted payload to tunnel %s (%d bytes)", tunnelID, len(body))
		default:
			log.Printf("[webhook] send buffer full for tunnel %s, dropping payload", tunnelID)
			http.Error(w, `{"error":"tunnel send buffer full"}`, http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"forwarded","tunnel_id":"%s"}`, tunnelID)
	}
}
