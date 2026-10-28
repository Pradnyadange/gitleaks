package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

const PromptVersion = "v1"

var disableCacheForTest = false

type TriageOptions struct {
	Offline     bool
	DryRun      bool
	Concurrency int
	MaxFindings int
	Model       string
}

type TriageStats struct {
	Verdicts     map[string]int
	Sources      map[string]int
	APICalls     int
	CacheHits    int
	LLMSuccesses int
	LLMFailures  int
}

const CacheFilename = ".secretsentinel-cache.json"

type cacheEntry struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Source     string  `json:"source"`
}

func getCacheKey(fingerprint, model string) string {
	return fingerprint + "|" + model + "|" + PromptVersion
}

func TriageFindings(ctx context.Context, findings []EnrichedFinding, client LLMClient, opts TriageOptions) ([]EnrichedFinding, TriageStats) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 3
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 50
	}
	if opts.Model == "" {
		opts.Model = "default-model"
	}
	if opts.DryRun {
		return DryRunTriage(findings, opts)
	}

	cache := make(map[string]cacheEntry)
	if !disableCacheForTest {
		cache = loadCache()
	}
	var cacheMu sync.Mutex

	stats := TriageStats{
		Verdicts: make(map[string]int),
		Sources:  make(map[string]int),
	}
	var apiCalls int32
	var cacheHits int32
	var llmSuccesses int32
	var llmFailures int32

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)

	// Print system prompt once for dry run
	if opts.DryRun {
		fmt.Println("DRY RUN - nothing sent")
		fmt.Printf("--- SYSTEM PROMPT ---\n%s\n---------------------\n", SystemPrompt)
	}

	processedCount := 0
	for i := range findings {
		if processedCount >= opts.MaxFindings {
			break
		}
		processedCount++

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			f := &findings[idx]
			cacheKey := getCacheKey(f.Fingerprint, opts.Model)

			if !opts.Offline && !disableCacheForTest {
				cacheMu.Lock()
				if cached, found := cache[cacheKey]; found && cached.Source == "llm" {
					cacheMu.Unlock()
					atomic.AddInt32(&cacheHits, 1)
					f.Triage = &Triage{
						Verdict:    cached.Verdict,
						Confidence: cached.Confidence,
						Reason:     cached.Reason,
						Source:     cached.Source,
						Cached:     true,
					}
					return
				}
				cacheMu.Unlock()
			}

			if opts.Offline || client == nil {
				heuristic := HeuristicClassify(*f)
				f.Triage = &heuristic
				return
			}

			userPrompt := BuildUserPrompt(*f)
			if opts.DryRun {
				fmt.Printf("--- USER PROMPT (Finding: %s) ---\n%s---------------------------------\n", f.Fingerprint, userPrompt)
				heuristic := HeuristicClassify(*f)
				heuristic.Reason = "[DRY-RUN] " + heuristic.Reason
				f.Triage = &heuristic
				return
			}

			rawResp, err := client.Classify(ctx, SystemPrompt, userPrompt)
			atomic.AddInt32(&apiCalls, 1)

			var triage Triage
			parsedOK := false
			if err == nil {
				var parsed struct {
					Verdict    string  `json:"verdict"`
					Confidence float64 `json:"confidence"`
					Reason     string  `json:"reason"`
				}
				if json.Unmarshal([]byte(rawResp), &parsed) == nil {
					if isValidVerdict(parsed.Verdict) {
						parsedOK = true
						conf := parsed.Confidence
						if conf < 0 {
							conf = 0
						}
						if conf > 1.0 {
							conf = 1.0
						}
						reason := parsed.Reason
						if len(reason) > 160 {
							reason = reason[:160]
						}
						triage = Triage{
							Verdict:    parsed.Verdict,
							Confidence: conf,
							Reason:     reason,
							Source:     "llm",
							Cached:     false,
						}
					}
				}
			}

			if !parsedOK {
				atomic.AddInt32(&llmFailures, 1)
				errMsg := "unknown parsing or validation error"
				if err != nil {
					errMsg = err.Error()
				}
				log.Warn().Msgf("llm triage failed, falling back to heuristics: %s", errMsg)
				triage = HeuristicClassify(*f)
			} else {
				atomic.AddInt32(&llmSuccesses, 1)
				f.Triage = &triage
				if !disableCacheForTest {
					cacheMu.Lock()
					cache[cacheKey] = cacheEntry{
						Verdict:    triage.Verdict,
						Confidence: triage.Confidence,
						Reason:     triage.Reason,
						Source:     triage.Source,
					}
					cacheMu.Unlock()
				}
			}

			f.Triage = &triage
		}(i)
	}

	wg.Wait()
	if !disableCacheForTest {
		saveCache(cache)
	}

	stats.APICalls = int(apiCalls)
	stats.CacheHits = int(cacheHits)
	stats.LLMSuccesses = int(llmSuccesses)
	stats.LLMFailures = int(llmFailures)

	for _, f := range findings {
		if f.Triage != nil {
			stats.Verdicts[f.Triage.Verdict]++
			stats.Sources[f.Triage.Source]++
		}
	}

	return findings, stats
}

func isValidVerdict(v string) bool {
	return v == "real_secret" || v == "likely_false_positive" || v == "needs_review"
}

func loadCache() map[string]cacheEntry {
	cache := make(map[string]cacheEntry)
	data, err := os.ReadFile(CacheFilename)
	if err != nil {
		return cache
	}
	_ = json.Unmarshal(data, &cache)
	return cache
}

func saveCache(cache map[string]cacheEntry) {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err == nil {
		_ = os.WriteFile(CacheFilename, data, 0644)
	}
}
