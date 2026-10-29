package audit

import (
	"strings"
	"testing"
)

func TestRiskScoringAndFactors(t *testing.T) {
	t.Run("nil triage handled gracefully", func(t *testing.T) {
		f := EnrichedFinding{
			PathType:      "source",
			InHistoryOnly: false,
			Entropy:       4.5,
			Triage:        nil,
		}
		score, level, factors, impact := CalculateRisk(f)
		if score < 0 || score > 100 {
			t.Errorf("score %d out of bounds 0-100", score)
		}
		if level != "high" && level != "critical" {
			t.Errorf("unexpected level for active source finding: %s", level)
		}
		if len(factors) == 0 {
			t.Errorf("expected risk factors to be populated")
		}
		if impact == "" {
			t.Errorf("expected risk impact text")
		}
	})

	t.Run("llm likely_false_positive maps to info level", func(t *testing.T) {
		f := EnrichedFinding{
			PathType:      "test",
			InHistoryOnly: true,
			Entropy:       2.0,
			Triage: &Triage{
				Verdict:    "likely_false_positive",
				Confidence: 0.95,
				Source:     "llm",
			},
		}
		_, level, _, _ := CalculateRisk(f)
		if level != "info" {
			t.Errorf("expected level 'info' for LLM false positive, got %s", level)
		}
	})

	t.Run("score clamping bounds 0 and 100", func(t *testing.T) {
		lowF := EnrichedFinding{
			PathType:      "test",
			InHistoryOnly: true,
			Entropy:       1.0,
			Triage: &Triage{
				Verdict:    "likely_false_positive",
				Confidence: 1.0,
				Source:     "llm",
			},
		}
		scoreLow, _, _, _ := CalculateRisk(lowF)
		if scoreLow < 0 {
			t.Errorf("score clamped below 0: %d", scoreLow)
		}

		highF := EnrichedFinding{
			RuleID:        "aws-access-key",
			PathType:      "source",
			InHistoryOnly: false,
			Entropy:       5.0,
			Triage: &Triage{
				Verdict:    "real_secret",
				Confidence: 1.0,
				Source:     "llm",
			},
		}
		scoreHigh, _, _, _ := CalculateRisk(highF)
		if scoreHigh > 100 {
			t.Errorf("score clamped above 100: %d", scoreHigh)
		}
	})

	t.Run("risk factors and impact verification for rules and path types", func(t *testing.T) {
		f := EnrichedFinding{
			RuleID:        "github-pat",
			PathType:      "config",
			InHistoryOnly: false,
			Entropy:       4.5,
			Triage: &Triage{
				Verdict:    "real_secret",
				Confidence: 0.9,
				Source:     "llm",
			},
		}
		score, level, factors, impact := CalculateRisk(f)
		if score <= 0 || level == "" {
			t.Errorf("expected valid score and level")
		}
		if len(factors) == 0 {
			t.Errorf("expected non-empty risk factors")
		}
		if impact == "" || !strings.Contains(impact, "repository access") {
			t.Errorf("expected source control impact text, got: %s", impact)
		}
	})
}
