// Package crypto implements hybrid encryption for CipherRelay using
// RSA-2048 (OAEP/SHA-256) for key exchange and AES-256-GCM for
// symmetric data encryption. This ensures webhook payloads remain
// confidential even if the relay server is compromised.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/0xZKc0de/cipherrelay/internal/models"
)

const (
	// rsaKeySize is the RSA key size in bits (2048-bit as per spec).
	rsaKeySize = 2048

	// aesKeySize is the AES key size in bytes (256-bit).
	aesKeySize = 32
)

// GenerateRSAKeyPair generates a new RSA-2048 key pair and returns
// the private key along with the public key encoded in PEM format.
func GenerateRSAKeyPair() (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return privateKey, pubPEM, nil
}

// ParsePublicKeyPEM parses a PEM-encoded RSA public key and returns
// the corresponding *rsa.PublicKey.
func ParsePublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an RSA public key")
	}

	return rsaPub, nil
}

// EncryptPayload performs hybrid encryption on plaintext data:
//  1. Generates a random AES-256 symmetric key.
//  2. Encrypts the plaintext with AES-256-GCM.
//  3. Encrypts the AES key with RSA-OAEP (SHA-256) using the recipient's public key.
//
// Returns an EncryptedPayload containing all components needed for decryption.
func EncryptPayload(publicKey *rsa.PublicKey, plaintext []byte) (*models.EncryptedPayload, error) {
	// Step 1: Generate a random AES-256 key.
	aesKey := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}

	// Step 2: Encrypt the plaintext with AES-GCM.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	cipherText := gcm.Seal(nil, nonce, plaintext, nil)

	// Step 3: Encrypt the AES key with RSA-OAEP.
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt AES key: %w", err)
	}

	return &models.EncryptedPayload{
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
		CipherText:   cipherText,
	}, nil
}

// DecryptPayload performs hybrid decryption on an EncryptedPayload:
//  1. Decrypts the AES key using RSA-OAEP (SHA-256) with the recipient's private key.
//  2. Decrypts the ciphertext using AES-256-GCM with the recovered key and nonce.
//
// Returns the original plaintext data.
func DecryptPayload(privateKey *rsa.PrivateKey, payload *models.EncryptedPayload) ([]byte, error) {
	// Step 1: Decrypt the AES key with RSA-OAEP.
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, payload.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decrypt AES key: %w", err)
	}

	// Step 2: Decrypt the ciphertext with AES-GCM.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, payload.Nonce, payload.CipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	return plaintext, nil
}
