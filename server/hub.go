// Package server implements the CipherRelay public relay server,
// including the WebSocket hub for managing tunnel connections and
// HTTP handlers for webhook ingress.
package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

// TunnelClient represents a connected client with an active tunnel.
// It holds the WebSocket connection, the client's RSA public key
// (used to encrypt payloads), and a buffered send channel.
type TunnelClient struct {
	ID        string
	PublicKey *rsa.PublicKey
	Conn      *websocket.Conn
	Send      chan []byte
}

// Hub maintains a thread-safe registry of active tunnel clients.
// It provides methods to register, unregister, and look up clients
// by their tunnel ID.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]*TunnelClient
}

// NewHub creates and returns a new Hub with an initialized client map.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]*TunnelClient),
	}
}

// Register adds a new TunnelClient to the hub under the given tunnel ID.
func (h *Hub) Register(client *TunnelClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client.ID] = client
	log.Printf("[hub] registered tunnel: %s", client.ID)
}

// Unregister removes a tunnel client from the hub and closes its
// send channel and WebSocket connection.
func (h *Hub) Unregister(tunnelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	client, ok := h.clients[tunnelID]
	if !ok {
		return
	}

	close(client.Send)
	client.Conn.Close()
	delete(h.clients, tunnelID)
	log.Printf("[hub] unregistered tunnel: %s", tunnelID)
}

// GetClient returns the TunnelClient for the given tunnel ID,
// or nil if no client is registered with that ID.
func (h *Hub) GetClient(tunnelID string) *TunnelClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clients[tunnelID]
}

// GenerateTunnelID creates a cryptographically random 16-byte hex string
// to serve as a unique tunnel identifier.
func GenerateTunnelID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// WritePump reads messages from the client's send channel and writes
// them to the WebSocket connection. It runs as a goroutine and exits
// when the send channel is closed.
func (c *TunnelClient) WritePump() {
	defer c.Conn.Close()

	for msg := range c.Send {
		if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			log.Printf("[hub] write error for tunnel %s: %v", c.ID, err)
			return
		}
	}
}

// ReadPump reads messages from the WebSocket connection and discards them.
// It detects client disconnections and triggers cleanup via the hub.
// It runs as a goroutine.
func (c *TunnelClient) ReadPump(hub *Hub) {
	defer hub.Unregister(c.ID)

	for {
		if _, _, err := c.Conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[hub] read error for tunnel %s: %v", c.ID, err)
			}
			return
		}
		// Client messages after registration are ignored (MVP).
	}
}
