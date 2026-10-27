package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type GeminiClient struct {
	model  string
	apiKey string
}

func NewGeminiClient(model, apiKey string) *GeminiClient {
	return &GeminiClient{
		model:  model,
		apiKey: apiKey,
	}
}

type geminiRequest struct {
	SystemInstruction struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"system_instruction"`
	Contents []struct {
		Role  string `json:"role"`
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"contents"`
	GenerationConfig struct {
		Temperature      float64         `json:"temperature"`
		ResponseMimeType string          `json:"responseMimeType"`
		ResponseSchema   json.RawMessage `json:"responseSchema"`
	} `json:"generationConfig"`
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

func (c *GeminiClient) Classify(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", c.model)

	schema := json.RawMessage(`{
		"type": "OBJECT",
		"properties": {
			"verdict": { "type": "STRING" },
			"confidence": { "type": "NUMBER" },
			"reason": { "type": "STRING" }
		},
		"required": ["verdict", "confidence", "reason"]
	}`)

	var reqBody geminiRequest
	reqBody.SystemInstruction.Parts = []struct {
		Text string `json:"text"`
	}{{Text: systemPrompt}}

	reqBody.Contents = []struct {
		Role  string `json:"role"`
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	}{
		{
			Role: "user",
			Parts: []struct {
				Text string `json:"text"`
			}{{Text: userPrompt}},
		},
	}

	reqBody.GenerationConfig.Temperature = 0
	reqBody.GenerationConfig.ResponseMimeType = "application/json"
	reqBody.GenerationConfig.ResponseSchema = schema

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var lastErr error
	backoff := 1 * time.Second

	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-goog-api-key", c.apiKey)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("gemini api error status %d: %s", resp.StatusCode, string(bodyBytes))
			continue
		}

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("gemini api non-retryable error status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var gemResp geminiResponse
		if err := json.Unmarshal(bodyBytes, &gemResp); err != nil {
			return "", err
		}

		if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("empty response candidates from gemini api")
		}

		return gemResp.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("gemini api request failed after retries: %w", lastErr)
}
