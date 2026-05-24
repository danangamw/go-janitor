package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type webhookPayload struct {
	Text        string              `json:"text"`
	Attachments []webhookAttachment `json:"attachments"`
}

type webhookAttachment struct {
	Color  string         `json:"color"`
	Fields []webhookField `json:"fields"`
}

type webhookField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SendAlert sends a security alert to the configured webhook URL.
// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
// A webhook failure never causes a non-zero exit from the main process.
func SendAlert(ctx context.Context, webhookURL string, stats ScannerStats, host string, ts time.Time) {
	if webhookURL == "" {
		return
	}

	payload := webhookPayload{
		Text: "🚨 Go-Janitor Security Alert",
		Attachments: []webhookAttachment{
			{
				Color: "danger",
				Fields: []webhookField{
					{Title: "Host", Value: host, Short: true},
					{Title: "Critical CVEs Found", Value: fmt.Sprintf("%d", stats.ImagesWithCritical), Short: true},
					{Title: "High CVEs Found", Value: fmt.Sprintf("%d", stats.ImagesWithHigh), Short: true},
					{Title: "Scan Time", Value: ts.UTC().Format(time.RFC3339), Short: true},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook marshal failed", "error", err)
		return
	}

	backoff := time.Second
	for attempt := 1; attempt <= 3; attempt++ {
		if err := postWebhook(ctx, webhookURL, body); err == nil {
			return
		} else {
			slog.Warn("webhook attempt failed", "attempt", attempt, "error", err)
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	slog.Error("webhook failed after 3 attempts — alert not delivered")
}

func postWebhook(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
