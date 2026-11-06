package audit

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestContextExtractionMultiSecretRedaction(t *testing.T) {
	t.Run("Two adjacent .env lines each with a different secret: neither raw secret appears in context, prompts, or reports", func(t *testing.T) {
		secret1 := "ghp_111111111111111111111111111111111111"
		secret2 := "ghp_222222222222222222222222222222222222"
		content := "GITHUB_TOKEN_1=" + secret1 + "\n" +
			"GITHUB_TOKEN_2=" + secret2 + "\n"

		tmpDir := t.TempDir()
		envFile := filepath.Join(tmpDir, ".env")
		if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write temp .env: %v", err)
		}

		finding1Ref := FileFindingRef{
			StartLine:    1,
			EndLine:      1,
			Secret:       secret1,
			MaskedSecret: MaskSecret(secret1),
			RuleID:       "github-pat",
		}
		finding2Ref := FileFindingRef{
			StartLine:    2,
			EndLine:      2,
			Secret:       secret2,
			MaskedSecret: MaskSecret(secret2),
			RuleID:       "github-pat",
		}

		neighbors := []FileFindingRef{finding1Ref, finding2Ref}

		// Extract context for finding 1 (line 1), requesting 5 context lines
		ctx1 := ExtractContextWithNeighbors(tmpDir, "dir", "", ".env", 1, 5, secret1, finding1Ref.MaskedSecret, false, neighbors, "github-pat")

		// Verify neither raw secret1 nor raw secret2 appears in ctx1
		for _, line := range ctx1 {
			if strings.Contains(line, secret1) {
				t.Fatalf("security violation: raw secret1 found in context of finding 1: %s", line)
			}
			if strings.Contains(line, secret2) {
				t.Fatalf("security violation: neighbor raw secret2 leaked into context of finding 1: %s", line)
			}
		}

		// Extract context for finding 2 (line 2), requesting 5 context lines
		ctx2 := ExtractContextWithNeighbors(tmpDir, "dir", "", ".env", 2, 5, secret2, finding2Ref.MaskedSecret, false, neighbors, "github-pat")

		// Verify neither raw secret1 nor raw secret2 appears in ctx2
		for _, line := range ctx2 {
			if strings.Contains(line, secret1) {
				t.Fatalf("security violation: neighbor raw secret1 leaked into context of finding 2: %s", line)
			}
			if strings.Contains(line, secret2) {
				t.Fatalf("security violation: raw secret2 found in context of finding 2: %s", line)
			}
		}

		// Check prompt generation with BuildUserPrompt
		f1 := EnrichedFinding{
			RuleID:       "github-pat",
			File:         ".env",
			StartLine:    1,
			EndLine:      1,
			MaskedSecret: finding1Ref.MaskedSecret,
			CodeContext:  ctx1,
			RawSecret:    secret1,
		}
		prompt1 := BuildUserPrompt(f1)
		if strings.Contains(prompt1, secret1) || strings.Contains(prompt1, secret2) {
			t.Fatalf("raw secret leaked into user prompt: %s", prompt1)
		}

		f2 := EnrichedFinding{
			RuleID:       "github-pat",
			File:         ".env",
			StartLine:    2,
			EndLine:      2,
			MaskedSecret: finding2Ref.MaskedSecret,
			CodeContext:  ctx2,
			RawSecret:    secret2,
		}
		prompt2 := BuildUserPrompt(f2)
		if strings.Contains(prompt2, secret1) || strings.Contains(prompt2, secret2) {
			t.Fatalf("raw secret leaked into user prompt: %s", prompt2)
		}

		// Check DryRun output
		findingsList := []EnrichedFinding{f1, f2}
		_, _ = DryRunTriage(findingsList, TriageOptions{})

		// Check Markdown and HTML Reports
		mdReport := GenerateReport(findingsList, "markdown")
		if strings.Contains(mdReport, secret1) || strings.Contains(mdReport, secret2) {
			t.Fatalf("raw secret leaked into Markdown report: %s", mdReport)
		}
		htmlReport := GenerateReport(findingsList, "html")
		if strings.Contains(htmlReport, secret1) || strings.Contains(htmlReport, secret2) {
			t.Fatalf("raw secret leaked into HTML report: %s", htmlReport)
		}

		// Check JSON marshal output
		jsonData, err := json.Marshal(findingsList)
		if err != nil {
			t.Fatalf("json marshal error: %v", err)
		}
		jsonStr := string(jsonData)
		if strings.Contains(jsonStr, secret1) || strings.Contains(jsonStr, secret2) {
			t.Fatalf("raw secret leaked into JSON output: %s", jsonStr)
		}
	})

	t.Run("Testing in real temp git repo (git mode)", func(t *testing.T) {
		repoDir := t.TempDir()

		// Initialize temp git repository
		cmd := exec.Command("git", "init")
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git init failed: %v, output: %s", err, string(out))
		}
		cmd = exec.Command("git", "config", "user.name", "Tester")
		cmd.Dir = repoDir
		_ = cmd.Run()
		cmd = exec.Command("git", "config", "user.email", "tester@example.com")
		cmd.Dir = repoDir
		_ = cmd.Run()

		secretA := "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		secretB := "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		filePath := filepath.Join(repoDir, "config.py")
		code := "# configuration\nKEY_A = \"" + secretA + "\"\nKEY_B = \"" + secretB + "\"\n# end\n"
		if err := os.WriteFile(filePath, []byte(code), 0644); err != nil {
			t.Fatalf("failed to write config.py: %v", err)
		}

		cmd = exec.Command("git", "add", "config.py")
		cmd.Dir = repoDir
		_ = cmd.Run()
		cmd = exec.Command("git", "commit", "-m", "add config")
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git commit failed: %v, output: %s", err, string(out))
		}

		// Retrieve commit hash
		cmd = exec.Command("git", "rev-parse", "HEAD")
		cmd.Dir = repoDir
		commitOut, err := cmd.Output()
		if err != nil {
			t.Fatalf("git rev-parse HEAD failed: %v", err)
		}
		commitSHA := strings.TrimSpace(string(commitOut))

		neighbors := []FileFindingRef{
			{StartLine: 2, EndLine: 2, Secret: secretA, MaskedSecret: MaskSecret(secretA), RuleID: "github-pat"},
			{StartLine: 3, EndLine: 3, Secret: secretB, MaskedSecret: MaskSecret(secretB), RuleID: "github-pat"},
		}

		ctxA := ExtractContextWithNeighbors(repoDir, "git", commitSHA, "config.py", 2, 5, secretA, MaskSecret(secretA), false, neighbors, "github-pat")
		for _, line := range ctxA {
			if strings.Contains(line, secretA) || strings.Contains(line, secretB) {
				t.Fatalf("raw secret leaked in git mode context: %s", line)
			}
		}
	})

	t.Run("Single-line secret and multi-line key in the same file", func(t *testing.T) {
		singleSecret := "ghp_333333333333333333333333333333333333"
		multiSecret := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nsaAAAAAwEAAQAAAYEA07V9+\n-----END OPENSSH PRIVATE KEY-----"

		content := "API_TOKEN=" + singleSecret + "\n" +
			"SSH_KEY=\n" + multiSecret + "\n"

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "credentials.txt")
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write credentials.txt: %v", err)
		}

		neighbors := []FileFindingRef{
			{StartLine: 1, EndLine: 1, Secret: singleSecret, MaskedSecret: MaskSecret(singleSecret), RuleID: "github-pat"},
			{StartLine: 3, EndLine: 6, Secret: multiSecret, MaskedSecret: MaskSecret(multiSecret), RuleID: "private-key"},
		}

		// Context for single secret on line 1
		ctxSingle := ExtractContextWithNeighbors(tmpDir, "dir", "", "credentials.txt", 1, 10, singleSecret, MaskSecret(singleSecret), false, neighbors, "github-pat")
		for _, line := range ctxSingle {
			if strings.Contains(line, singleSecret) {
				t.Fatalf("raw single secret leaked: %s", line)
			}
			if strings.Contains(line, "b3BlbnNzaC1rZXktdjE") || strings.Contains(line, "BEGIN OPENSSH") {
				t.Fatalf("multi-line key body/header leaked in single secret context: %s", line)
			}
		}

		// Context for multi-line secret on line 3
		ctxMulti := ExtractContextWithNeighbors(tmpDir, "dir", "", "credentials.txt", 3, 10, multiSecret, MaskSecret(multiSecret), false, neighbors, "private-key")
		for _, line := range ctxMulti {
			if strings.Contains(line, singleSecret) {
				t.Fatalf("single secret leaked into multi-line secret context: %s", line)
			}
			if strings.Contains(line, "b3BlbnNzaC1rZXktdjE") || strings.Contains(line, "BEGIN OPENSSH") {
				t.Fatalf("multi-line key body/header leaked in multi-line context: %s", line)
			}
		}

		// Verify [REDACTED MULTI-LINE SECRET] appears in ctxSingle and ctxMulti
		foundRedactedSingle := false
		for _, line := range ctxSingle {
			if strings.Contains(line, "[REDACTED MULTI-LINE SECRET]") {
				foundRedactedSingle = true
			}
		}
		if !foundRedactedSingle {
			t.Errorf("expected [REDACTED MULTI-LINE SECRET] placeholder in neighbor context")
		}

		foundRedactedMulti := false
		for _, line := range ctxMulti {
			if strings.Contains(line, "[REDACTED MULTI-LINE SECRET]") {
				foundRedactedMulti = true
			}
		}
		if !foundRedactedMulti {
			t.Errorf("expected [REDACTED MULTI-LINE SECRET] placeholder in multi-line context")
		}
	})

	t.Run("Single-file single-secret regression check", func(t *testing.T) {
		secret := "ghp_444444444444444444444444444444444444"
		content := "line 1\nTOKEN=" + secret + "\nline 3\n"

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "app.py")
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write app.py: %v", err)
		}

		ctx := ExtractContext(tmpDir, "dir", "", "app.py", 2, 2, secret, MaskSecret(secret), false)
		if len(ctx) != 3 {
			t.Fatalf("expected 3 context lines, got %d", len(ctx))
		}
		if strings.Contains(ctx[1], secret) {
			t.Fatalf("raw secret leaked in regression check: %s", ctx[1])
		}
		if !strings.Contains(ctx[1], "ghp_****44") {
			t.Fatalf("expected masked secret in context line: %s", ctx[1])
		}
	})
}

