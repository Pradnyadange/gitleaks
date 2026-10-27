package audit

import "strings"

func MaskSecret(secret string) string {
	if len(secret) < 16 {
		if len(secret) == 0 {
			return ""
		}
		return strings.Repeat("*", len(secret))
	}
	prefix := secret[:4]
	suffix := secret[len(secret)-2:]
	return prefix + "****" + suffix
}
