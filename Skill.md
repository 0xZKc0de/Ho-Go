# Project Specification: CipherRelay (E2EE Webhook Tunnel)

## 1. Project Overview
CipherRelay is a secure, minimum viable product (MVP) for an End-to-End Encrypted (E2EE) Webhook forwarding tunnel built in Go. It serves as a highly secure alternative to tools like ngrok, specifically designed to protect webhook payloads (e.g., from Stripe or GitHub) from being intercepted or read by the tunneling server itself. 

The architecture consists of two main components:
- **Public Server:** A stateless server that listens for incoming Webhooks via HTTP, encrypts the entire payload and headers, and forwards them over a WebSocket connection to the intended local client.
- **Local Client:** A CLI tool running on the developer's machine that generates encryption keys, connects to the Public Server via WebSocket, receives the encrypted payloads, decrypts them locally, and forwards them as standard HTTP requests to the developer's local application (e.g., `localhost:8080`).

## 2. Core Architecture & Cryptography (Hybrid Encryption)
Since webhook payloads can be large, you must implement **Hybrid Encryption**:
1. **Client Setup:** Upon startup, the client generates an RSA-2048 key pair. It connects to the server's WebSocket endpoint and sends its Public Key. The server registers the client and returns a unique `TunnelID` and a public webhook URL.
2. **Receiving a Webhook (Server-side):** When a webhook hits the server's HTTP endpoint for a specific `TunnelID`:
   - The server generates a random, temporary AES-256 symmetric key.
   - The server encrypts the webhook data (HTTP method, headers, and body) using `AES-GCM` with this temporary key.
   - The server encrypts the temporary AES key itself using the Client's `RSA Public Key` (via `RSA-OAEP`).
   - The server sends the encrypted AES key, the AES nonce, and the encrypted payload to the client via WebSocket using JSON.
3. **Processing (Client-side):** The client receives the JSON over WebSocket, uses its `RSA Private Key` to decrypt the AES key, then uses the AES key to decrypt the payload, reconstructs the original HTTP request, and forwards it to the local port.

## 3. Strict Rules & Constraints
- **Language:** Go (Golang) 1.21+.
- **Dependencies:** Use the standard library for HTTP and Cryptography. You are only allowed to use `github.com/gorilla/websocket` for the WebSocket implementation.
- **No Databases:** The server must be completely stateless. Use in-memory maps to manage active WebSocket connections and their associated `TunnelID`s.
- **No Extra Features:** Do not add authentication systems, databases, or UI. Keep it strictly as an MVP CLI client and a lightweight server.

## 4. Your Tasks (What to do)
Please act as a Senior Go Security Engineer and generate the complete, working code for this project. 
You are free to design the project's folder structure, module setup, and file naming conventions as you see fit for a modern Go project. 

Please provide:
1. **The Cryptography logic:** Functions for generating keys, encrypting, and decrypting using the hybrid approach (RSA + AES-GCM).
2. **The Server application:** Handling WebSocket upgrades, registering clients, generating Tunnel IDs, receiving HTTP POST/GET webhooks, encrypting them, and routing them to the correct WebSocket.
3. **The Client application:** Key generation, establishing the WebSocket connection, receiving data, decrypting it, and making the local HTTP POST request.
4. **Instructions:** Brief instructions on how to initialize the `go.mod` file, install the gorilla/websocket dependency, and run both the server and the client.

Please output the code systematically, clearly indicating the file paths/names you have chosen for each block of code.