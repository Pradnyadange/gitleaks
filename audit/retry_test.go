package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryDelay(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{`{"error": {"details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "44s"}]}}`, 44 * time.Second},
		{`{"error": {"details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "44.762005836s"}]}}`, 44*time.Second + 762005836*time.Nanosecond},
		{`{"error": {}}`, 0},
		{`invalid json`, 0},
		{`{"error": {"details": [{"retryDelay": "garbage"}]}}`, 0},
	}

	for _, tt := range tests {
		got := parseRetryDelay([]byte(tt.input))
		if got != tt.expected {
			t.Errorf("parseRetryDelay(%q) = %v; want %v", tt.input, got, tt.expected)
		}
	}
}

func TestGeminiNon429NonRetry(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": {"message": "invalid argument"}}`))
	}))
	defer srv.Close()

	client := &GeminiClient{
		Model:   "gemini-1.5-pro",
		APIKey:  "dummy-key",
		BaseURL: srv.URL,
	}

	_, err := client.Classify(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatalf("expected error on 400 Bad Request, got nil")
	}

	if count := atomic.LoadInt32(&requestCount); count != 1 {
		t.Errorf("expected exactly 1 request for non-429 4xx, got %d", count)
	}
}

func TestGemini429RetryThenSuccess(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqNum := atomic.AddInt32(&requestCount, 1)
		if reqNum == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": {"details": [{"retryDelay": "10ms"}]}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {
					"parts": [{"text": "{\"verdict\": \"real_secret\", \"confidence\": 0.95, \"reason\": \"ok\"}"}]
				}
			}]
		}`))
	}))
	defer srv.Close()

	client := &GeminiClient{
		Model:   "gemini-1.5-pro",
		APIKey:  "dummy-key",
		BaseURL: srv.URL,
	}

	resp, err := client.Classify(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == "" {
		t.Errorf("expected non-empty response")
	}

	if count := atomic.LoadInt32(&requestCount); count != 2 {
		t.Errorf("expected 2 requests after 429 retry, got %d", count)
	}

	if retries := client.RetriesAfter429(); retries != 1 {
		t.Errorf("expected 1 retry after 429 tracked, got %d", retries)
	}
}

type mockRetryTrackerClient struct {
	response string
	err      error
	retries  int
}

func (m *mockRetryTrackerClient) Classify(ctx context.Context, sys, usr string) (string, error) {
	return m.response, m.err
}

func (m *mockRetryTrackerClient) RetriesAfter429() int {
	return m.retries
}

func TestTriageStatsRetriesAndCacheNonStorage(t *testing.T) {
	tempParent := os.TempDir()
	tmpDir, err := os.MkdirTemp(tempParent, "retry-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(tempParent)
		_ = os.RemoveAll(tmpDir)
	}()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	disableCacheForTest = false
	defer func() { disableCacheForTest = true }()

	finding := EnrichedFinding{
		Fingerprint:  "fp-test-retry-cache",
		RuleID:       "test-rule",
		File:         "test.go",
		MaskedSecret: "1234****56",
		SecretLength: 16,
		CodeContext:  []string{"KEY=1234****56"},
		PathType:     "source",
	}

	t.Run("failed LLM call does not store heuristic fallback in cache", func(t *testing.T) {
		_ = os.Remove(CacheFilename)
		mock := &mockRetryTrackerClient{
			err:     fmt.Errorf("API error 400"),
			retries: 0,
		}

		findings, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			MaxFindings: 1,
			Model:       "test-model",
		})

		if stats.LLMFailures != 1 {
			t.Errorf("expected 1 LLM failure, got %d", stats.LLMFailures)
		}
		if findings[0].Triage.Source != "heuristic" {
			t.Errorf("expected heuristic fallback, got %s", findings[0].Triage.Source)
		}

		cache := loadCache()
		key := getCacheKey(finding.Fingerprint, "test-model")
		if _, found := cache[key]; found {
			t.Errorf("failed LLM call should not be stored in cache")
		}
	})

	t.Run("429-then-success is counted as LLM success and stored in cache", func(t *testing.T) {
		_ = os.Remove(CacheFilename)
		mock := &mockRetryTrackerClient{
			response: `{"verdict": "real_secret", "confidence": 0.9, "reason": "valid"}`,
			retries:  2,
		}

		findings, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			MaxFindings: 1,
			Model:       "test-model",
		})

		if stats.LLMSuccesses != 1 {
			t.Errorf("expected 1 LLM success, got %d", stats.LLMSuccesses)
		}
		if stats.RetriesAfter429 != 2 {
			t.Errorf("expected 2 retries after 429, got %d", stats.RetriesAfter429)
		}
		if findings[0].Triage.Source != "llm" {
			t.Errorf("expected llm source, got %s", findings[0].Triage.Source)
		}

		cache := loadCache()
		key := getCacheKey(finding.Fingerprint, "test-model")
		if entry, found := cache[key]; !found || entry.Source != "llm" {
			t.Errorf("successful call after retry should be stored in cache as llm")
		}
	})
}

