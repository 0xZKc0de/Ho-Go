package client

import "fmt"

// PrintBanner outputs a formatted ASCII banner to the terminal
// displaying the active tunnel configuration and encryption details.
func PrintBanner(tunnelID, webhookURL, forwardURL string) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   CipherRelay Tunnel Active                 ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Tunnel ID:   %s\n", tunnelID)
	fmt.Printf("║  Webhook URL: %s\n", webhookURL)
	fmt.Printf("║  Forwarding:  %s\n", forwardURL)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Encryption:  RSA-2048 + AES-256-GCM (Hybrid E2EE)         ║")
	fmt.Println("║  Status:      Listening for encrypted payloads...           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}
