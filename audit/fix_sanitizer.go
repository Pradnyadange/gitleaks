package audit

import (
	"strings"
)

// SanitizeOutput replaces every RawSecret present in findings with its MaskedSecret.
func SanitizeOutput(text string, findings []EnrichedFinding) string {
	if text == "" || len(findings) == 0 {
		return text
	}

	for _, f := range findings {
		if f.RawSecret != "" && f.MaskedSecret != "" {
			text = strings.ReplaceAll(text, f.RawSecret, f.MaskedSecret)
		}
	}
	return text
}

