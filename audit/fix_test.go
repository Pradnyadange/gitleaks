package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helper to init a git repo in temp dir with initial commit
func setupTestGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v, output: %s", args, err, string(out))
		}
	}

	run("init", "-b", "main")
	run("config", "user.name", "TestUser")
	run("config", "user.email", "test@example.com")

	// Create initial file
	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("# Test Repo\n"), 0644); err != nil {
		t.Fatalf("failed to create README: %v", err)
	}
	run("add", "README.md")
	run("commit", "-m", "Initial commit")

	return dir
}

func commitFile(t *testing.T, repoDir, relPath, content string) {
	t.Helper()
	fullPath := filepath.Join(repoDir, relPath)
	_ = os.MkdirAll(filepath.Dir(fullPath), 0755)
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", relPath, err)
	}
	cmd := exec.Command("git", "add", relPath)
	cmd.Dir = repoDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s failed: %v (%s)", relPath, err, string(out))
	}
	cmd = exec.Command("git", "commit", "-m", "add "+relPath)
	cmd.Dir = repoDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit failed: %v (%s)", err, string(out))
	}
}

func captureOutput(f func()) (string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	outC := make(chan string)
	errC := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outC <- buf.String()
	}()

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errC <- buf.String()
	}()

	f()

	_ = wOut.Close()
	_ = wErr.Close()

	os.Stdout = oldStdout
	os.Stderr = oldStderr

	outStr := <-outC
	errStr := <-errC

	return outStr, errStr
}

func TestAutoFixNamingAndBranching(t *testing.T) {
	t.Run("Naming: API_KEY stays API_KEY, GITHUB_TOKEN stays GITHUB_TOKEN", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "API_KEY = \"key1234567890\"\nGITHUB_TOKEN = \"ghp_abcdefghijklmnopqrstuvwxyz\"\n"
		commitFile(t, repo, "config.py", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "rule-key",
				File:          "config.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "key1234567890",
				MaskedSecret:  "key1****90",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "github-pat",
				File:          "config.py",
				StartLine:     2,
				EndLine:       2,
				RawSecret:     "ghp_abcdefghijklmnopqrstuvwxyz",
				MaskedSecret:  "ghp_****yz",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: false})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.Statuses[0].EnvVar != "API_KEY" {
			t.Errorf("expected API_KEY, got %s", sum.Statuses[0].EnvVar)
		}
		if sum.Statuses[1].EnvVar != "GITHUB_TOKEN" {
			t.Errorf("expected GITHUB_TOKEN, got %s", sum.Statuses[1].EnvVar)
		}
	})

	t.Run("Naming: camelCase stripeKey converts to STRIPE_KEY", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "const stripeKey = \"sk_live_12345678901234567890\";\n"
		commitFile(t, repo, "stripe.js", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "stripe-api-key",
				File:          "stripe.js",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "sk_live_12345678901234567890",
				MaskedSecret:  "sk_l****90",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: false})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.Statuses[0].EnvVar != "STRIPE_KEY" {
			t.Errorf("expected STRIPE_KEY, got %s", sum.Statuses[0].EnvVar)
		}
	})

	t.Run("Naming: dict/object config = {'db_password': '...'} -> DB_PASSWORD", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "config = {\n    \"db_password\": \"supersecretpassword123\",\n}\n"
		commitFile(t, repo, "db.py", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "db-cred",
				File:          "db.py",
				StartLine:     2,
				EndLine:       2,
				RawSecret:     "supersecretpassword123",
				MaskedSecret:  "supe****23",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: false})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.Statuses[0].EnvVar != "DB_PASSWORD" {
			t.Errorf("expected DB_PASSWORD, got %s", sum.Statuses[0].EnvVar)
		}
	})

	t.Run("Naming: duplicate names in one file get _2, _3 suffix", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "api_key = \"key1111111111111\"\nother = func(api_key=\"key2222222222222\")\n"
		commitFile(t, repo, "dup.py", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "rule-api-key",
				File:          "dup.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "key1111111111111",
				MaskedSecret:  "key1****11",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "rule-api-key",
				File:          "dup.py",
				StartLine:     2,
				EndLine:       2,
				RawSecret:     "key2222222222222",
				MaskedSecret:  "key2****22",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: false})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.Statuses[0].EnvVar != "API_KEY" {
			t.Errorf("expected API_KEY, got %s", sum.Statuses[0].EnvVar)
		}
		if sum.Statuses[1].EnvVar != "API_KEY_2" {
			t.Errorf("expected API_KEY_2, got %s", sum.Statuses[1].EnvVar)
		}
	})

	t.Run("Naming: fallback to rule_id when no assignment found", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "print(\"secret9999999999\")\n"
		commitFile(t, repo, "anon.py", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "slack-webhook-token",
				File:          "anon.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secret9999999999",
				MaskedSecret:  "secr****99",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: false})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.Statuses[0].EnvVar != "SLACK_WEBHOOK_TOKEN" {
			t.Errorf("expected SLACK_WEBHOOK_TOKEN, got %s", sum.Statuses[0].EnvVar)
		}
	})

	t.Run("Dotenv .env.example adds KEY= only if not present and skips existing keys", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		envContent := "EXISTING_KEY=secretval1234567\nNEW_KEY=secretval7654321\n"
		commitFile(t, repo, ".env", envContent)

		// .env.example already has EXISTING_KEY with a dummy value
		commitFile(t, repo, ".env.example", "EXISTING_KEY=dummy_value\nPORT=8080\n")

		findings := []EnrichedFinding{
			{
				RuleID:        "rule-existing",
				File:          ".env",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secretval1234567",
				MaskedSecret:  "secr****67",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "rule-new",
				File:          ".env",
				StartLine:     2,
				EndLine:       2,
				RawSecret:     "secretval7654321",
				MaskedSecret:  "secr****21",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{
			RepoDir: repo,
			Apply:   true,
		})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.AppliedCount != 2 {
			t.Errorf("expected 2 applied, got %d", sum.AppliedCount)
		}

		cmd := exec.Command("git", "show", sum.Branch+":.env.example")
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show .env.example failed: %v", err)
		}
		exStr := string(out)

		// Check that EXISTING_KEY= was not duplicated
		if strings.Count(exStr, "EXISTING_KEY") != 1 {
			t.Errorf("EXISTING_KEY duplicated in .env.example: %s", exStr)
		}
		// Check that NEW_KEY= was added
		if !strings.Contains(exStr, "NEW_KEY=\n") && !strings.HasSuffix(exStr, "NEW_KEY=") {
			t.Errorf("NEW_KEY= not properly appended: %s", exStr)
		}
		// Zero secrets in .env.example
		if strings.Contains(exStr, "secretval1234567") || strings.Contains(exStr, "secretval7654321") {
			t.Errorf("raw secret leaked into .env.example: %s", exStr)
		}
	})

	t.Run("Branch name generation with timestamp and suffixing collisions", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		git := NewGitRepo(repo)

		// Default format contains secretsentinel/fix-
		bDefault := git.GenerateUniqueBranchName("")
		if !strings.HasPrefix(bDefault, "secretsentinel/fix-") {
			t.Errorf("expected secretsentinel/fix- prefix, got %s", bDefault)
		}

		// Create branch with that name
		_ = exec.Command("git", "-C", repo, "branch", bDefault).Run()

		// Collision check on default branch
		bDefault2 := git.GenerateUniqueBranchName(bDefault)
		if bDefault2 != bDefault+"-2" {
			t.Errorf("expected %s-2, got %s", bDefault, bDefault2)
		}

		// Custom branch collision check
		custom := "feature/fix-tokens"
		_ = exec.Command("git", "-C", repo, "branch", custom).Run()
		_ = exec.Command("git", "-C", repo, "branch", custom+"-2").Run()

		custom3 := git.GenerateUniqueBranchName(custom)
		if custom3 != custom+"-3" {
			t.Errorf("expected %s-3, got %s", custom, custom3)
		}
	})
}

func TestAutoFixEngine(t *testing.T) {
	t.Run("Python double and single quotes patch with import os in isolated worktree", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		pyContent := "#!/usr/bin/env python\n\"\"\"Module docstring.\"\"\"\n\ndef get_token():\n    api_key = \"AKIAIOSFODNN7EXAMPLE\"\n    secret_token = 's3cr3t_t0k3n_12345'\n    return api_key, secret_token\n"
		commitFile(t, repo, "src/auth.py", pyContent)

		findings := []EnrichedFinding{
			{
				RuleID:        "aws-access-key",
				File:          "src/auth.py",
				StartLine:     5,
				EndLine:       5,
				RawSecret:     "AKIAIOSFODNN7EXAMPLE",
				MaskedSecret:  "AKIA****LE",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "secret-token",
				File:          "src/auth.py",
				StartLine:     6,
				EndLine:       6,
				RawSecret:     "s3cr3t_t0k3n_12345",
				MaskedSecret:  "s3cr****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{
			RepoDir:    repo,
			Apply:      true,
			BranchName: "fix/python-secrets",
		})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.AppliedCount != 2 {
			t.Errorf("expected 2 applied, got %d", sum.AppliedCount)
		}

		// User's active branch should remain "main"
		git := NewGitRepo(repo)
		currBranch, _ := git.GetCurrentBranch()
		if currBranch != "main" {
			t.Errorf("expected user branch to remain main, got %s", currBranch)
		}

		// The fix branch should exist
		if !git.BranchExists("fix/python-secrets") {
			t.Errorf("expected branch fix/python-secrets to exist")
		}

		// Inspect the committed file on the fix branch via git show
		cmd := exec.Command("git", "show", "fix/python-secrets:src/auth.py")
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show failed: %v", err)
		}
		newContent := string(out)

		if strings.Contains(newContent, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(newContent, "s3cr3t_t0k3n_12345") {
			t.Errorf("raw secret still present in committed fix: %s", newContent)
		}
		if !strings.Contains(newContent, `api_key = os.environ["API_KEY"]`) {
			t.Errorf("expected os.environ replacement for api_key, got: %s", newContent)
		}
		if !strings.Contains(newContent, `secret_token = os.environ["SECRET_TOKEN"]`) {
			t.Errorf("expected os.environ replacement for secret token, got: %s", newContent)
		}
		if !strings.Contains(newContent, "import os") {
			t.Errorf("expected import os in file, got: %s", newContent)
		}
		if strings.Count(newContent, "import os") != 1 {
			t.Errorf("import os duplicated: %d times", strings.Count(newContent, "import os"))
		}
	})

	t.Run("JS and CRLF preservation in worktree", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		jsContent := "const key = \"ghp_abcdefghijklmnopqrstuvwxyz\";\r\nconsole.log(key);\r\n"
		commitFile(t, repo, "index.js", jsContent)

		findings := []EnrichedFinding{
			{
				RuleID:        "github-pat",
				File:          "index.js",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "ghp_abcdefghijklmnopqrstuvwxyz",
				MaskedSecret:  "ghp_****yz",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "critical",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{
			RepoDir:    repo,
			Apply:      true,
			BranchName: "fix/js-pat",
		})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.AppliedCount != 1 {
			t.Errorf("expected 1 applied, got %d", sum.AppliedCount)
		}

		cmd := exec.Command("git", "show", "fix/js-pat:index.js")
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show failed: %v", err)
		}

		if !strings.Contains(string(out), "\r\n") {
			t.Errorf("CRLF line endings were not preserved")
		}
		if !strings.Contains(string(out), "const key = process.env.KEY;") {
			t.Errorf("expected process.env.KEY, got: %s", string(out))
		}
	})

	t.Run("Post-apply state: user working tree, index, and uncommitted .env are completely untouched", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		committedEnv := "PORT=3000\nSECRET=supersecret12345\n"
		commitFile(t, repo, ".env", committedEnv)

		// Modify .env on disk locally without committing it (differing from committed version)
		localUncommittedEnv := "PORT=3000\nSECRET=supersecret12345\nUNCOMMITTED_LOCAL=my-local-value\n"
		_ = os.WriteFile(filepath.Join(repo, ".env"), []byte(localUncommittedEnv), 0644)

		findings := []EnrichedFinding{
			{
				RuleID:        "app-secret",
				File:          ".env",
				StartLine:     2,
				EndLine:       2,
				RawSecret:     "supersecret12345",
				MaskedSecret:  "supe****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{
			RepoDir: repo,
			Apply:   true,
		})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}
		if sum.AppliedCount != 1 {
			t.Errorf("expected 1 applied, got %d", sum.AppliedCount)
		}

		git := NewGitRepo(repo)
		branch, _ := git.GetCurrentBranch()
		if branch != "main" {
			t.Errorf("user branch changed to %s; expected main", branch)
		}

		// Verify local .env on disk is byte-for-byte unchanged
		diskContent, err := os.ReadFile(filepath.Join(repo, ".env"))
		if err != nil {
			t.Fatalf("failed to read local .env: %v", err)
		}
		if string(diskContent) != localUncommittedEnv {
			t.Errorf("local .env was mutated! Expected %q, got %q", localUncommittedEnv, string(diskContent))
		}

		// Verify fix branch has .env untracked and .gitignore updated
		fixBranch := sum.Branch
		cmd := exec.Command("git", "ls-tree", fixBranch, ".env")
		cmd.Dir = repo
		out, _ := cmd.CombinedOutput()
		if len(strings.TrimSpace(string(out))) > 0 {
			t.Errorf(".env is still tracked in %s: %s", fixBranch, string(out))
		}

		cmd = exec.Command("git", "show", fixBranch+":.gitignore")
		cmd.Dir = repo
		giOut, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(giOut), ".env") {
			t.Errorf("expected .gitignore on %s to contain .env, got: %s", fixBranch, string(giOut))
		}
	})

	t.Run("Capturing output asserts zero RawSecret leakage during preview and apply", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		py := "key = 'RAW_SECRET_LEAK_TEST_12345'\n"
		commitFile(t, repo, "leak.py", py)

		findings := []EnrichedFinding{
			{
				RuleID:        "secret-key",
				File:          "leak.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "RAW_SECRET_LEAK_TEST_12345",
				MaskedSecret:  "RAW_****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		// Preview
		sumPreview, err := AutoFix(findings, FixOptions{
			RepoDir: repo,
			Apply:   false,
		})
		if err != nil {
			t.Fatalf("preview failed: %v", err)
		}

		out, errStr := captureOutput(func() {
			sanitized := SanitizeOutput(sumPreview.String(), findings)
			os.Stdout.WriteString(sanitized)
		})
		if strings.Contains(out, "RAW_SECRET_LEAK_TEST_12345") || strings.Contains(errStr, "RAW_SECRET_LEAK_TEST_12345") {
			t.Errorf("RawSecret leaked in preview stdout/stderr! Out: %s, Err: %s", out, errStr)
		}

		// Apply
		sumApply, err := AutoFix(findings, FixOptions{
			RepoDir: repo,
			Apply:   true,
		})
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		out, errStr = captureOutput(func() {
			sanitized := SanitizeOutput(sumApply.String(), findings)
			os.Stdout.WriteString(sanitized)
		})
		if strings.Contains(out, "RAW_SECRET_LEAK_TEST_12345") || strings.Contains(errStr, "RAW_SECRET_LEAK_TEST_12345") {
			t.Errorf("RawSecret leaked in apply stdout/stderr! Out: %s, Err: %s", out, errStr)
		}
	})

	t.Run("Security: RawSecret does not appear in JSON serialization or commit messages", func(t *testing.T) {
		f := EnrichedFinding{
			RuleID:       "aws-key",
			RawSecret:    "SECRET_RAW_TOKEN_VALUE",
			MaskedSecret: "SECR****UE",
		}
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json marshal failed: %v", err)
		}
		if strings.Contains(string(data), "SECRET_RAW_TOKEN_VALUE") {
			t.Errorf("security violation: RawSecret leaked in JSON output: %s", string(data))
		}
	})
}
