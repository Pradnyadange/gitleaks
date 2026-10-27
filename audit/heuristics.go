package audit

import (
	"fmt"
	"strings"
)

func HeuristicClassify(f EnrichedFinding) Triage {
	reason := "Heuristic fallback evaluation based on path type and context patterns."
	confidence := 0.5
	verdict := "needs_review"

	if f.PathType == "test" || f.PathType == "example" || f.PathType == "docs" {
		verdict = "likely_false_positive"
		confidence = 0.7
		reason = fmt.Sprintf("Path type %q indicates non-production code.", f.PathType)
	}

	keywords := []string{"example", "changeme", "your_", "dummy", "placeholder", "xxxx"}
	combinedText := strings.ToLower(f.MaskedSecret)
	for _, line := range f.CodeContext {
		combinedText += " " + strings.ToLower(line)
	}

	for _, kw := range keywords {
		if strings.Contains(combinedText, kw) {
			verdict = "likely_false_positive"
			confidence = 0.8
			reason = fmt.Sprintf("Matched placeholder keyword %q in context or secret.", kw)
			break
		}
	}

	return Triage{
		Verdict:    verdict,
		Confidence: confidence,
		Reason:     reason,
		Source:     "heuristic",
		Cached:     false,
	}
}
