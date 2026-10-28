package audit

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestTriageCacheAndFailures(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp dir: %v", err)
	}
	defer os.Chdir(origDir)

	disableCacheForTest = false
	defer func() { disableCacheForTest = true }()

	finding := EnrichedFinding{
		Fingerprint:  "fp-cache-isolation-test",
		RuleID:       "test-rule",
		File:         "src/main.go",
		MaskedSecret: "1234****56",
		SecretLength: 16,
		CodeContext:  []string{"API_KEY=1234****56"},
		PathType:     "source",
	}

	t.Run("offline run does not write heuristic results to the cache", func(t *testing.T) {
		mock := &MockLLMClient{}
		_, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     true,
			MaxFindings: 1,
			Model:       "gemini-1.5-pro",
		})
		if stats.APICalls != 0 {
			t.Fatalf("expected 0 API calls offline, got %d", stats.APICalls)
		}

		_, err := os.Stat(CacheFilename)
		if !os.IsNotExist(err) {
			cacheData := loadCache()
			if len(cacheData) > 0 {
				t.Errorf("expected cache to remain empty after offline run, got %d entries", len(cacheData))
			}
		}

		mock.Response = `{"verdict": "real_secret", "confidence": 0.9, "reason": "Valid key"}`
		_, stats2 := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-1.5-pro",
		})
		if stats2.APICalls != 1 || stats2.CacheHits != 0 {
			t.Errorf("expected 1 API call and 0 cache hits, got calls=%d hits=%d", stats2.APICalls, stats2.CacheHits)
		}
	})

	t.Run("successful LLM call is cached, and the second run makes 0 LLM calls", func(t *testing.T) {
		_ = os.Remove(CacheFilename)
		mock := &MockLLMClient{
			Response: `{"verdict": "real_secret", "confidence": 0.9, "reason": "Valid key"}`,
		}
		_, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-1.5-pro",
		})
		if stats.APICalls != 1 {
			t.Fatalf("expected 1 API call, got %d", stats.APICalls)
		}

		_, stats2 := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-1.5-pro",
		})
		// On cache hit, new API calls made in this run is 0, and cache hits is 1
		if stats2.APICalls != 0 || stats2.CacheHits != 1 {
			t.Errorf("expected 0 new API calls and 1 cache hit, got calls=%d hits=%d", stats2.APICalls, stats2.CacheHits)
		}
	})

	t.Run("changing the model name invalidates the cache", func(t *testing.T) {
		mock := &MockLLMClient{
			Response: `{"verdict": "real_secret", "confidence": 0.9, "reason": "Valid key"}`,
		}
		_, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-2.5-flash",
		})
		if stats.APICalls != 1 || stats.CacheHits != 0 {
			t.Errorf("expected cache miss (1 API call made, 0 cache hits) when changing model, got calls=%d hits=%d", stats.APICalls, stats.CacheHits)
		}
	})

	t.Run("a failed LLM call falls back to heuristics and is not cached", func(t *testing.T) {
		_ = os.Remove(CacheFilename)
		mock := &MockLLMClient{
			Err: errors.New("API rate limit exceeded"),
		}
		_, stats := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-fail-test",
		})
		if stats.LLMFailures != 1 {
			t.Errorf("expected 1 LLM failure, got %d", stats.LLMFailures)
		}

		mock.Err = nil
		mock.Response = `{"verdict": "needs_review", "confidence": 0.5, "reason": "Resolved"}`
		_, stats2 := TriageFindings(context.Background(), []EnrichedFinding{finding}, mock, TriageOptions{
			Offline:     false,
			MaxFindings: 1,
			Model:       "gemini-fail-test",
		})
		if stats2.APICalls != 1 || stats2.CacheHits != 0 {
			t.Errorf("expected failure not to be cached (1 API call made), got calls=%d hits=%d", stats2.APICalls, stats2.CacheHits)
		}
	})
}
