// Package models defines shared data types used across the CipherRelay
// server and client for encrypted payload transport and tunnel registration.
package models

// WebhookData represents the original HTTP webhook request
// that is captured by the server before encryption.
type WebhookData struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// EncryptedPayload is the wire format sent from the server to the client
// over WebSocket. It contains all the components needed for the client
// to decrypt the original webhook data using its RSA private key.
type EncryptedPayload struct {
	// EncryptedKey is the AES-256 symmetric key, encrypted with the
	// client's RSA public key using RSA-OAEP (SHA-256).
	EncryptedKey []byte `json:"encrypted_key"`

	// Nonce is the 12-byte initialization vector used for AES-GCM encryption.
	Nonce []byte `json:"nonce"`

	// CipherText is the webhook data (serialized WebhookData JSON),
	// encrypted with AES-256-GCM using the symmetric key and nonce.
	CipherText []byte `json:"cipher_text"`
}

// ClientRegistration is the initial message sent by the client to the
// server over WebSocket to register a new tunnel. It contains the
// client's RSA public key in PEM-encoded format.
type ClientRegistration struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

// RegistrationResponse is sent by the server back to the client after
// a successful tunnel registration. It contains the unique tunnel ID
// and the public webhook URL that external services should POST to.
type RegistrationResponse struct {
	TunnelID   string `json:"tunnel_id"`
	WebhookURL string `json:"webhook_url"`
}
