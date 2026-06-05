package client

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/0xZKc0de/cipherrelay/internal/models"
)

// ForwardWebhook sends the decrypted webhook data as an HTTP request
// to the local target service, preserving the original method, headers, and body.
// It uses exponential backoff to retry if the local service is temporarily down.
func ForwardWebhook(client *http.Client, targetURL string, data *models.WebhookData) {
	maxRetries := 5
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest(data.Method, targetURL, bytes.NewReader(data.Body))
		if err != nil {
			log.Printf("[forward] create request error: %v", err)
			return
		}

		// Restore original headers.
		for key, values := range data.Headers {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}

		resp, err := client.Do(req)
		
		// Success
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			log.Printf("[forward] → %s %s → %d (%d bytes response)",
				data.Method, targetURL, resp.StatusCode, len(body))
			return
		}

		// Failure - retry logic
		log.Printf("[forward] error on attempt %d/%d: %v", attempt, maxRetries, err)
		if attempt < maxRetries {
			log.Printf("[forward] retrying in %v...", backoff)
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
		}
	}

	log.Printf("[forward] ❌ failed to forward webhook after %d attempts", maxRetries)
}
