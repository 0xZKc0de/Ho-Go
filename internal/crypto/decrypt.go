package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/0xZKc0de/cipherrelay/internal/models"
)

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
