package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/0xZKc0de/cipherrelay/internal/models"
)

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
	
	// Zero out the AES key from memory now that it is encrypted and used.
	for i := range aesKey {
		aesKey[i] = 0
	}

	if err != nil {
		return nil, fmt.Errorf("RSA encrypt AES key: %w", err)
	}

	return &models.EncryptedPayload{
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
		CipherText:   cipherText,
	}, nil
}
