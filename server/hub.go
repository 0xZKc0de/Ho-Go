package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
)

// Hub maintains a thread-safe registry of active tunnel clients.
// It provides methods to register, unregister, and look up clients
// by their tunnel ID.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]*TunnelClient
	logger  *slog.Logger
}

// NewHub creates and returns a new Hub with an initialized client map.
func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[string]*TunnelClient),
		logger:  logger,
	}
}

// Register adds a new TunnelClient to the hub under the given tunnel ID.
func (h *Hub) Register(client *TunnelClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client.ID] = client
	h.logger.Info("registered tunnel", "tunnel_id", client.ID, "active", len(h.clients))
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
	h.logger.Info("unregistered tunnel", "tunnel_id", tunnelID, "active", len(h.clients))
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
