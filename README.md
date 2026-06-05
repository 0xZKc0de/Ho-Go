# CipherRelay

**End-to-End Encrypted Webhook Forwarding Tunnel**

CipherRelay is a secure, production-ready webhook forwarding tunnel built in Go. It uses hybrid encryption (RSA-2048 + AES-256-GCM) to ensure that webhook payloads are encrypted end-to-end — the relay server **never** sees plaintext data.

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

## Production Features

- **Authentication**: Secure your server with pre-shared tokens so only authorized clients can connect.
- **Static Tunnel IDs**: Request custom, predictable tunnel URLs (e.g., `my-stripe-env`) instead of random hex strings.
- **Client Retries**: Exponential backoff retry mechanism ensures webhooks aren't lost if your local app is briefly down or restarting.
- **Structured Logging**: JSON logging via `log/slog` on the server for easy integration with Datadog, ELK, etc.
- **TLS Support**: Run the server securely with standard TLS certificates (`wss://` and `https://`).
- **12-Factor Ready**: Configure via CLI flags or Environment Variables.

---

## Quick Start

⚠️ **IMPORTANT**: You must run the server, client, and curl command in **three separate terminal windows** at the same time. The tunnel only exists while the client is connected!

### 1. Install dependencies

```bash
go mod tidy
```

### 2. Start the server (Terminal 1)

Keep this running! You can secure it by passing an auth token:
```bash
go run ./cmd/server -addr :8080 -base-url http://localhost:8080 -auth-tokens "my-secret-token"
```

### 3. Start the client (Terminal 2)

Keep this running! It will connect to the server. Here we request a static ID (`my-dev-env`) and pass the auth token:
```bash
go run ./cmd/client -server ws://localhost:8080/ws -forward http://localhost:3000 -auth-token "my-secret-token" -id "my-dev-env"
```

### 4. Send a test webhook (Terminal 3)

Because we requested a static ID, the URL is predictable:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"event":"payment.completed","amount":4200}' \
  http://localhost:8080/hook/my-dev-env
```

The payload will be encrypted by the server, sent over WebSocket, decrypted by the client, and forwarded to `http://localhost:3000`. If localhost is down, the client will retry up to 5 times.

---

## Configuration Reference

Both Server and Client can be configured via Environment Variables or CLI flags. Flags take precedence over environment variables.

### Server

| CLI Flag | Environment Variable | Default | Description |
|----------|----------------------|---------|-------------|
| `-addr` | `CR_ADDR` | `:8080` | Listen address |
| `-base-url` | `CR_BASE_URL` | `http://localhost:8080` | Public base URL for webhooks |
| `-auth-tokens` | `CR_AUTH_TOKENS` | *(empty)* | Comma-separated list of valid tokens (empty disables auth) |
| `-cert` | `CR_CERT` | *(empty)* | TLS certificate file path |
| `-key` | `CR_KEY` | *(empty)* | TLS key file path |

### Client

| CLI Flag | Environment Variable | Default | Description |
|----------|----------------------|---------|-------------|
| `-server` | `CR_SERVER` | `ws://localhost:8080/ws` | Server WebSocket URL |
| `-forward` | `CR_FORWARD` | `http://localhost:3000` | Local target URL to forward to |
| `-auth-token` | `CR_AUTH_TOKEN` | *(empty)* | Token to authenticate with server |
| `-id` | `CR_TUNNEL_ID` | *(empty)* | Request a specific static tunnel ID |

---

## License

MIT
