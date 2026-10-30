package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultilineSecretRedactionAndMasking(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ssh_key.pem")

	sshKeyContent := "line before\n" +
		"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n" +
		"NhAAAAAwEAAQAAAYEA07V9+\n" +
		"-----END OPENSSH PRIVATE KEY-----\n" +
		"line after\n"

	err := os.WriteFile(filePath, []byte(sshKeyContent), 0644)
	if err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	t.Run("7-line OpenSSH key in dir mode redacts body and headers completely", func(t *testing.T) {
		secretVal := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nsaAAAAAwEAAQAAAYEA07V9+\n-----END OPENSSH PRIVATE KEY-----"
		masked := MaskSecret(secretVal)

		if !strings.Contains(masked, "MULTI-LINE SECRET") {
			t.Errorf("expected multi-line secret mask, got %q", masked)
		}

		ctx := ExtractContext(tmpDir, "dir", "", "ssh_key.pem", 2, 5, secretVal, masked, false, "private-key")

		for _, line := range ctx {
			if strings.Contains(line, "b3BlbnNzaC1rZXktdjE") || strings.Contains(line, "BEGIN OPENSSH") || strings.Contains(line, "END OPENSSH") {
				t.Errorf("security violation: private key body or header line appeared in context: %q", line)
			}
		}

		// Verify surrounding non-secret lines are kept
		foundBefore, foundAfter := false, false
		for _, line := range ctx {
			if strings.Contains(line, "line before") {
				foundBefore = true
			}
			if strings.Contains(line, "line after") {
				foundAfter = true
			}
		}
		if !foundBefore || !foundAfter {
			t.Errorf("expected surrounding non-secret lines to be kept, got context: %v", ctx)
		}
	})

	t.Run("single-line secrets behave exactly as before (regression)", func(t *testing.T) {
		singleSecret := "AKIAIOSFODNN7EXAMPLE"
		masked := MaskSecret(singleSecret)
		if masked != "AKIA****LE" {
			t.Errorf("single line secret regression: got %q", masked)
		}
	})

	t.Run("BuildUserPrompt output contains no body line", func(t *testing.T) {
		finding := EnrichedFinding{
			RuleID:       "private-key",
			File:         "ssh_key.pem",
			MaskedSecret: "[MULTI-LINE SECRET, 5 lines]",
			CodeContext:  []string{"line before", "[REDACTED MULTI-LINE SECRET]", "line after"},
			PathType:     "source",
		}
		prompt := BuildUserPrompt(finding)
		if strings.Contains(prompt, "b3BlbnNzaC1rZXktdjE") || strings.Contains(prompt, "BEGIN OPENSSH") {
			t.Errorf("prompt contains raw key body/headers")
		}
	})
}

