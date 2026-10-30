package audit

import (
	"fmt"
	"strings"
)

func MaskSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if strings.Contains(secret, "\n") || strings.Contains(secret, "PRIVATE KEY") || len(strings.Split(secret, "\n")) > 1 {
		lines := strings.Count(secret, "\n") + 1
		return fmt.Sprintf("[MULTI-LINE SECRET, %d lines]", lines)
	}
	if len(secret) < 16 {
		return strings.Repeat("*", len(secret))
	}
	prefix := secret[:4]
	suffix := secret[len(secret)-2:]
	return prefix + "****" + suffix
}
