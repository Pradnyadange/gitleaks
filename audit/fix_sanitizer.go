package audit

import (
	"strings"
)

// SanitizeOutput replaces every RawSecret present in findings with its MaskedSecret.
// It also sanitizes individual lines for multi-line secrets.
func SanitizeOutput(text string, findings []EnrichedFinding) string {
	if text == "" || len(findings) == 0 {
		return text
	}

	for _, f := range findings {
		if f.RawSecret != "" && f.MaskedSecret != "" {
			text = strings.ReplaceAll(text, f.RawSecret, f.MaskedSecret)

			// If multi-line, also sanitize any non-empty lines of RawSecret
			if strings.Contains(f.RawSecret, "\n") {
				for _, line := range strings.Split(f.RawSecret, "\n") {
					trimmed := strings.TrimSpace(line)
					if len(trimmed) > 4 {
						text = strings.ReplaceAll(text, trimmed, "[REDACTED MULTI-LINE SECRET]")
					}
				}
			}
		}
	}
	return text
}

