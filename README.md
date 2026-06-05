# CipherRelay

**End-to-End Encrypted Webhook Forwarding Tunnel**

CipherRelay is a secure webhook forwarding tunnel built in Go. It uses hybrid encryption (RSA-2048 + AES-256-GCM) to ensure that webhook payloads are encrypted end-to-end — the relay server **never** sees plaintext data.

> A privacy-first alternative to ngrok for webhook development.

---

## Architecture

```
                        ┌──────────────────────────┐
                        │     CipherRelay Server   │
  Stripe/GitHub ──────► │  (Stateless Public Relay) │
  POST /hook/{id}       │                          │
                        │  1. Generate random AES  │
                        │  2. Encrypt body (AES-GCM)│
                        │  3. Encrypt AES key (RSA) │
                        │  4. Send over WebSocket   │
                        └──────────┬───────────────┘
                                   │ WebSocket (E2EE)
                                   │
                        ┌──────────▼───────────────┐
                        │     CipherRelay Client   │
                        │   (Local Dev Machine)     │
                        │                          │
                        │  1. Decrypt AES key (RSA) │
                        │  2. Decrypt body (AES-GCM)│
                        │  3. Forward to localhost  │
                        └──────────┬───────────────┘
                                   │ HTTP
                                   ▼
                        ┌──────────────────────────┐
                        │   Your Local App          │
                        │   (localhost:3000)         │
                        └──────────────────────────┘
```

### Encryption Flow (Hybrid E2EE)

1. **Client** generates an RSA-2048 key pair and sends the public key to the server via WebSocket.
2. **Server** receives a webhook, generates a random AES-256 key, encrypts the payload with AES-GCM, then encrypts the AES key with the client's RSA public key (RSA-OAEP/SHA-256).
3. **Client** decrypts the AES key using its RSA private key, then decrypts the payload with AES-GCM, and forwards the original HTTP request to localhost.

The server **never** has access to the private key — it can only encrypt, never decrypt.

---

## Project Structure

```
├── cmd/
│   ├── server/main.go      # Server entrypoint
│   └── client/main.go      # Client entrypoint
├── server/
│   ├── hub.go               # WebSocket hub & tunnel registry
│   └── handlers.go          # HTTP handlers (WS upgrade + webhook ingress)
├── internal/
│   ├── crypto/crypto.go     # Hybrid RSA + AES-GCM encryption
│   └── models/models.go     # Shared data types
├── go.mod
└── go.sum
```

---

## Prerequisites

- **Go 1.21+** (tested with Go 1.25)

---

## Quick Start

⚠️ **IMPORTANT**: You must run the server, client, and curl command in **three separate terminal windows** at the same time. The tunnel only exists while the client is connected!

### 1. Install dependencies

```bash
go mod tidy
```

### 2. Start the server (Terminal 1)

Keep this running!
```bash
go run ./cmd/server -addr :8080 -base-url http://localhost:8080
```

### 3. Start the client (Terminal 2)

Keep this running! It will connect to the server.
```bash
go run ./cmd/client -server ws://localhost:8080/ws -forward http://localhost:3000
```

The client will display:

```
╔══════════════════════════════════════════════════════════════╗
║                   CipherRelay Tunnel Active                 ║
╠══════════════════════════════════════════════════════════════╣
║  Tunnel ID:   <your-tunnel-id>
║  Webhook URL: http://localhost:8080/hook/<your-tunnel-id>
║  Forwarding:  http://localhost:3000
╠══════════════════════════════════════════════════════════════╣
║  Encryption:  RSA-2048 + AES-256-GCM (Hybrid E2EE)         ║
║  Status:      Listening for encrypted payloads...           ║
╚══════════════════════════════════════════════════════════════╝
```

### 4. Send a test webhook (Terminal 3)

Copy the `Tunnel ID` from Terminal 2 and replace `<your-tunnel-id>` below:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"event":"payment.completed","amount":4200}' \
  http://localhost:8080/hook/<your-tunnel-id>
```

The payload will be encrypted by the server, sent over WebSocket, decrypted by the client, and forwarded to `http://localhost:3000` with the original method, headers, and body preserved.

---

## CLI Reference

### Server

```
go run ./cmd/server [flags]

Flags:
  -addr       string   Server listen address (default ":8080")
  -base-url   string   Public base URL for webhook endpoints (default "http://localhost:8080")
```

### Client

```
go run ./cmd/client [flags]

Flags:
  -server     string   CipherRelay server WebSocket URL (default "ws://localhost:8080/ws")
  -forward    string   Local target URL to forward decrypted webhooks (default "http://localhost:3000")
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/gorilla/websocket` | v1.5.3 | WebSocket client/server |
| Go stdlib `crypto/*` | — | RSA-OAEP, AES-GCM, key generation |

---

## License

MIT
