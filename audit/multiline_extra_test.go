package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultilineKeyRedactionAndEdgeCases(t *testing.T) {
	// A 7-line OpenSSH key structure (6 lines of key)
	sshKey7Lines := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n" +
		"NhAAAAAwEAAQAAAYEA07V9+ExampleOpenSSHKeyLine3VeryLongRandomPayloadXYZ123\n" +
		"4567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/\n" +
		"ABCDEFGHIJKLMNO+PQRSTUVWXYZ/0123456789+abcdefghijklmnopqrstuvwxyz===\n" +
		"-----END OPENSSH PRIVATE KEY-----"

	t.Run("7-line OpenSSH key in dir mode: headers redacted, body redacted, mask reveals nothing", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "server.pem")
		fullContent := "header_info = True\n" + sshKey7Lines + "\nfooter_info = True\n"
		if err := os.WriteFile(filePath, []byte(fullContent), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		rawSecret := sshKey7Lines
		masked := MaskSecret(rawSecret)

		// Must reveal nothing about the body, returning fixed multi-line format
		if !strings.HasPrefix(masked, "[MULTI-LINE SECRET,") {
			t.Errorf("MaskSecret leaked or formatted improperly: %q", masked)
		}
		if strings.Contains(masked, "b3BlbnNzaC") || strings.Contains(masked, "ExampleOpenSSH") {
			t.Errorf("MaskSecret leaked body text: %q", masked)
		}

		// targetLine is 2, key is 6 lines (lines 2-7), footer is line 8.
		// contextLines: 10 so start is 0, end is 8.
		ctx := ExtractContext(tmpDir, "dir", "", "server.pem", 2, 10, rawSecret, masked, false, "private-key")

		for _, line := range ctx {
			if strings.Contains(line, "BEGIN OPENSSH") || strings.Contains(line, "END OPENSSH") || strings.Contains(line, "b3BlbnNzaC") {
				t.Errorf("security violation: private key line present in context: %q", line)
			}
		}

		// Surrounding non-secret lines kept
		foundBefore, foundAfter := false, false
		for _, line := range ctx {
			if strings.Contains(line, "header_info = True") {
				foundBefore = true
			}
			if strings.Contains(line, "footer_info = True") {
				foundAfter = true
			}
		}
		if !foundBefore || !foundAfter {
			t.Errorf("expected surrounding lines kept in dir mode, got context: %v", ctx)
		}
	})

	t.Run("7-line OpenSSH key in git mode", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		fileRel := "certs/id_ed25519"
		fullContent := "# Leading config line\n" + sshKey7Lines + "\n# Trailing config line\n"
		commitFile(t, repo, fileRel, fullContent)

		rawSecret := sshKey7Lines
		masked := MaskSecret(rawSecret)

		git := NewGitRepo(repo)
		sha, err := git.run("rev-parse", "HEAD")
		if err != nil {
			t.Fatalf("rev-parse failed: %v", err)
		}

		ctx := ExtractContext(repo, "git", sha, fileRel, 2, 10, rawSecret, masked, false, "private-key")

		for _, line := range ctx {
			if strings.Contains(line, "BEGIN OPENSSH") || strings.Contains(line, "END OPENSSH") || strings.Contains(line, "b3BlbnNzaC") {
				t.Errorf("security violation in git mode: key line present in context: %q", line)
			}
		}

		foundBefore, foundAfter := false, false
		for _, line := range ctx {
			if strings.Contains(line, "# Leading config line") {
				foundBefore = true
			}
			if strings.Contains(line, "# Trailing config line") {
				foundAfter = true
			}
		}
		if !foundBefore || !foundAfter {
			t.Errorf("expected surrounding lines kept in git mode, got context: %v", ctx)
		}
	})

	t.Run("Key starting at line 1 of file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "key_at_line_1.pem")
		fullContent := sshKey7Lines + "\nafter_key_line = 1\n"
		if err := os.WriteFile(filePath, []byte(fullContent), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		rawSecret := sshKey7Lines
		masked := MaskSecret(rawSecret)

		ctx := ExtractContext(tmpDir, "dir", "", "key_at_line_1.pem", 1, 10, rawSecret, masked, false, "private-key")

		for _, line := range ctx {
			if strings.Contains(line, "BEGIN OPENSSH") || strings.Contains(line, "b3BlbnNzaC") {
				t.Errorf("security violation: line 1 key leaked in context: %q", line)
			}
		}

		hasAfter := false
		for _, line := range ctx {
			if strings.Contains(line, "after_key_line = 1") {
				hasAfter = true
			}
		}
		if !hasAfter {
			t.Errorf("expected after_key_line kept, got: %v", ctx)
		}
	})

	t.Run("Key ending on the last line of file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "key_at_end.pem")
		fullContent := "before_key_line = 1\n" + sshKey7Lines + "\n"
		if err := os.WriteFile(filePath, []byte(fullContent), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		rawSecret := sshKey7Lines
		masked := MaskSecret(rawSecret)

		ctx := ExtractContext(tmpDir, "dir", "", "key_at_end.pem", 2, 10, rawSecret, masked, false, "private-key")

		for _, line := range ctx {
			if strings.Contains(line, "BEGIN OPENSSH") || strings.Contains(line, "END OPENSSH") || strings.Contains(line, "b3BlbnNzaC") {
				t.Errorf("security violation: key line leaked in context: %q", line)
			}
		}

		hasBefore := false
		for _, line := range ctx {
			if strings.Contains(line, "before_key_line = 1") {
				hasBefore = true
			}
		}
		if !hasBefore {
			t.Errorf("expected before_key_line kept, got: %v", ctx)
		}
	})
}
