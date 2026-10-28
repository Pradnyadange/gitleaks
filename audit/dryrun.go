package audit

import (
	"fmt"
)

// DryRunTriage prints the system and user prompts that would be sent to the LLM
// without making any external API calls or reading/writing the cache.
func DryRunTriage(findings []EnrichedFinding, opts TriageOptions) ([]EnrichedFinding, TriageStats) {
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 50
	}

	stats := TriageStats{
		Verdicts: make(map[string]int),
		Sources:  make(map[string]int),
	}

	fmt.Println("DRY RUN - nothing sent")
	fmt.Printf("--- SYSTEM PROMPT ---\n%s\n---------------------\n", SystemPrompt)

	processedCount := 0
	for i := range findings {
		if processedCount >= opts.MaxFindings {
			break
		}
		processedCount++

		f := &findings[i]
		userPrompt := BuildUserPrompt(*f)
		fmt.Printf("--- USER PROMPT (Finding: %s) ---\n%s---------------------------------\n", f.Fingerprint, userPrompt)

		heuristic := HeuristicClassify(*f)
		heuristic.Reason = "[DRY-RUN] " + heuristic.Reason
		f.Triage = &heuristic
	}

	for _, f := range findings {
		if f.Triage != nil {
			stats.Verdicts[f.Triage.Verdict]++
			stats.Sources[f.Triage.Source]++
		}
	}

	return findings, stats
}
