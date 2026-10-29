package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type GeminiClient struct {
	Model           string
	APIKey          string
	BaseURL         string
	HTTPClient      *http.Client
	retriesAfter429 int64
}

func (g *GeminiClient) RetriesAfter429() int {
	return int(atomic.LoadInt64(&g.retriesAfter429))
}

func NewGeminiClient(model, apiKey string) *GeminiClient {
	return &GeminiClient{
		Model:  model,
		APIKey: apiKey,
	}
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func parseRetryDelay(body []byte) time.Duration {
	var resp struct {
		Error struct {
			Details []map[string]interface{} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return 0
	}
	for _, detail := range resp.Error.Details {
		if val, ok := detail["retryDelay"].(string); ok {
			if d, err := time.ParseDuration(val); err == nil {
				return d
			}
		}
	}
	return 0
}

func (g *GeminiClient) Classify(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", g.Model)
	if g.BaseURL != "" {
		url = fmt.Sprintf("%s/v1beta/models/%s:generateContent", g.BaseURL, g.Model)
	}

	payload := map[string]interface{}{
		"systemInstruction": map[string]interface{}{
			"parts": []map[string]string{{"text": systemPrompt}},
		},
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{{"text": userPrompt}},
			},
		},
		"generationConfig": map[string]interface{}{
			"responseMimeType": "application/json",
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	var respBody []byte
	var statusCode int

	maxRetries := 5
	backoff := 1 * time.Second

	httpClient := http.DefaultClient
	if g.HTTPClient != nil {
		httpClient = g.HTTPClient
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-goog-api-key", g.APIKey)

		resp, err := httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries {
				return "", err
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}

		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		statusCode = resp.StatusCode

		if statusCode == http.StatusOK {
			break
		}

		// Fail immediately on 4xx except 429
		if statusCode >= 400 && statusCode < 500 && statusCode != http.StatusTooManyRequests {
			return "", fmt.Errorf("API error status %d: %s", statusCode, string(respBody))
		}

		// Retry only on 429 and 5xx
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			if attempt == maxRetries {
				return "", fmt.Errorf("API error status %d after %d retries: %s", statusCode, maxRetries, string(respBody))
			}

			waitDur := backoff
			if statusCode == http.StatusTooManyRequests {
				atomic.AddInt64(&g.retriesAfter429, 1)
				if delay := parseRetryDelay(respBody); delay > 0 {
					waitDur = delay + 1*time.Second
					if waitDur > 70*time.Second {
						waitDur = 70 * time.Second
					}
				}
			}

			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(waitDur):
				if statusCode != http.StatusTooManyRequests {
					backoff *= 2
				}
				continue
			}
		}

		return "", fmt.Errorf("unexpected API status %d: %s", statusCode, string(respBody))
	}

	var gemResp geminiResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return "", err
	}

	if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response candidates from gemini api")
	}

	return gemResp.Candidates[0].Content.Parts[0].Text, nil
}
