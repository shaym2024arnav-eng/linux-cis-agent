package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxAttempts = 3

// backoff is the wait before retry number attempt+1: 2s, then 8s. Tests shorten it.
var backoff = func(attempt int) time.Duration {
	return time.Duration(attempt*attempt*2) * time.Second
}

// Send POSTs payload as JSON over HTTPS, retrying on network and 5xx errors.
func Send(url, apiKey string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, msg)
			if resp.StatusCode < 500 {
				return lastErr // 4xx won't fix itself, so don't retry
			}
		}
		if attempt < maxAttempts {
			time.Sleep(backoff(attempt))
		}
	}
	return fmt.Errorf("send failed after %d attempts: %w", maxAttempts, lastErr)
}
