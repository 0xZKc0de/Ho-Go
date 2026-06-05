package server

import (
	"crypto/rsa"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// maxMessageSize is the maximum allowed WebSocket message size (10 MB).
	maxMessageSize = 10 << 20

	// pongWait is the maximum time to wait for a pong response from the client.
	pongWait = 60 * time.Second

	// pingPeriod is the interval at which pings are sent to the client.
	// Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
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

// WritePump reads messages from the client's send channel and writes
// them to the WebSocket connection. It also sends periodic pings to
// detect dead connections. Runs as a goroutine; exits when the send
// channel is closed.
func (c *TunnelClient) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.Send:
			if !ok {
				// Send channel closed — write a close frame.
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				// Don't log if the error is just a broken pipe when the client disconnects
				if !websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					// Silent
				}
				return
			}
		case <-ticker.C:
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ReadPump reads messages from the WebSocket connection and discards them.
// It enforces a read size limit and pong deadline to detect dead connections.
// Runs as a goroutine; triggers tunnel cleanup on exit.
func (c *TunnelClient) ReadPump(hub *Hub) {
	defer hub.Unregister(c.ID)

	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		if _, _, err := c.Conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				hub.logger.Error("read error", "tunnel_id", c.ID, "err", err)
			}
			return
		}
		// Client messages after registration are ignored (MVP).
	}
}
