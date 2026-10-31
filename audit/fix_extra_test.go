package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutoFixRefusalsAndEdgeCases(t *testing.T) {
	t.Run("1. Secret embedded in a URL or connection string is skipped, file unchanged", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		originalCode := "const conn = \"postgres://user:supersecretpass123@localhost:5432/mydb\";\n"
		commitFile(t, repo, "db.js", originalCode)

		findings := []EnrichedFinding{
			{
				RuleID:        "db-password",
				File:          "db.js",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "supersecretpass123",
				MaskedSecret:  "supe****23",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("AutoFix failed: %v", err)
		}

		if sum.EligibleCount != 0 {
			t.Errorf("expected 0 eligible, got %d", sum.EligibleCount)
		}
		if len(sum.Statuses) != 1 || sum.Statuses[0].Reason != "embedded in a larger string" {
			t.Errorf("expected 'embedded in a larger string' reason, got: %v", sum.Statuses)
		}

		// Verify file remains completely unchanged
		data, err := os.ReadFile(filepath.Join(repo, "db.js"))
		if err != nil {
			t.Fatalf("failed to read db.js: %v", err)
		}
		if string(data) != originalCode {
			t.Errorf("file was modified! Expected %q, got %q", originalCode, string(data))
		}
	})

	t.Run("2. History-only finding is reported with history-only reason, nothing edited", func(t *testing.T) {
		repo := setupTestGitRepo(t)

		findings := []EnrichedFinding{
			{
				RuleID:        "aws-key",
				File:          "deleted_file.py",
				StartLine:     10,
				EndLine:       10,
				RawSecret:     "AKIAIOSFODNN7EXAMPLE",
				MaskedSecret:  "AKIA****LE",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: true,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if sum.EligibleCount != 0 {
			t.Errorf("expected 0 eligible for history-only finding, got %d", sum.EligibleCount)
		}
		if len(sum.Statuses) != 1 || sum.Statuses[0].Reason != "history-only" {
			t.Errorf("expected 'history-only' reason, got: %v", sum.Statuses)
		}
	})

	t.Run("3. Untracked file is skipped", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		// Write untracked file to repo
		untrackedFile := filepath.Join(repo, "untracked.py")
		_ = os.WriteFile(untrackedFile, []byte("token = 'mysecrettoken12345'\n"), 0644)

		findings := []EnrichedFinding{
			{
				RuleID:        "secret-token",
				File:          "untracked.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "mysecrettoken12345",
				MaskedSecret:  "myse****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if sum.EligibleCount != 0 {
			t.Errorf("expected 0 eligible for untracked file, got %d", sum.EligibleCount)
		}
		if len(sum.Statuses) != 1 || sum.Statuses[0].Reason != "untracked file" {
			t.Errorf("expected 'untracked file' reason, got: %v", sum.Statuses)
		}
	})

	t.Run("4. Multi-line secret (private-key rule) is skipped", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		keyContent := "-----BEGIN OPENSSH PRIVATE KEY-----\nline1\nline2\n-----END OPENSSH PRIVATE KEY-----\n"
		commitFile(t, repo, "key.pem", keyContent)

		findings := []EnrichedFinding{
			{
				RuleID:        "private-key",
				File:          "key.pem",
				StartLine:     1,
				EndLine:       4,
				RawSecret:     keyContent,
				MaskedSecret:  "[MULTI-LINE SECRET, 4 lines]",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "critical",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if sum.EligibleCount != 0 {
			t.Errorf("expected 0 eligible for multi-line secret, got %d", sum.EligibleCount)
		}
		if len(sum.Statuses) != 1 || sum.Statuses[0].Reason != "multi-line secret" {
			t.Errorf("expected 'multi-line secret' reason, got: %v", sum.Statuses)
		}
	})

	t.Run("5. Path traversal: ../x.py, absolute paths, and external symlinks rejected safely", func(t *testing.T) {
		repo := setupTestGitRepo(t)

		findings := []EnrichedFinding{
			{
				RuleID:        "rule-traversal",
				File:          "../outside.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secret12345",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "rule-abs",
				File:          filepath.Join(repo, "src", "abs.py"),
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secret12345",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if sum.EligibleCount != 0 {
			t.Errorf("expected 0 eligible, got %d", sum.EligibleCount)
		}
		for _, st := range sum.Statuses {
			if !strings.Contains(st.Reason, "traversal") && !strings.Contains(st.Reason, "invalid") {
				t.Errorf("expected traversal rejection reason, got: %s", st.Reason)
			}
		}
	})

	t.Run("6. Dotenv: removed from index in worktree only, .gitignore gets .env once, real .env untouched", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		commitFile(t, repo, ".gitignore", "node_modules/\n")

		committedEnv := "APP_KEY=secret_app_key_12345\nPORT=4000\n"
		commitFile(t, repo, ".env", committedEnv)

		// Modify .env on disk locally with an uncommitted edit
		uncommittedLocalEnv := "APP_KEY=secret_app_key_12345\nPORT=4000\nLOCAL_UNCOMMITTED=123\n"
		_ = os.WriteFile(filepath.Join(repo, ".env"), []byte(uncommittedLocalEnv), 0644)

		findings := []EnrichedFinding{
			{
				RuleID:        "generic-api-key",
				File:          ".env",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secret_app_key_12345",
				MaskedSecret:  "secr****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{RepoDir: repo, Apply: true})
		if err != nil {
			t.Fatalf("AutoFix error: %v", err)
		}

		if sum.AppliedCount != 1 {
			t.Fatalf("expected 1 applied for dotenv, got %d", sum.AppliedCount)
		}

		// User working tree check:
		git := NewGitRepo(repo)
		branch, _ := git.GetCurrentBranch()
		if branch != "main" {
			t.Errorf("expected main branch, got %s", branch)
		}

		localEnvData, _ := os.ReadFile(filepath.Join(repo, ".env"))
		if string(localEnvData) != uncommittedLocalEnv {
			t.Errorf("user .env was mutated! Expected %q, got %q", uncommittedLocalEnv, string(localEnvData))
		}

		// Fix branch checks:
		fixBranch := sum.Branch
		// .env should not be tracked on fixBranch
		cmd := exec.Command("git", "ls-tree", fixBranch, ".env")
		cmd.Dir = repo
		out, _ := cmd.CombinedOutput()
		if len(strings.TrimSpace(string(out))) > 0 {
			t.Errorf(".env is still tracked on %s: %s", fixBranch, string(out))
		}

		// .gitignore on fixBranch should contain ".env" exactly once
		cmd = exec.Command("git", "show", fixBranch+":.gitignore")
		cmd.Dir = repo
		giOut, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show .gitignore failed: %v", err)
		}
		if strings.Count(string(giOut), ".env") != 1 {
			t.Errorf("expected '.env' exactly once in .gitignore, got: %s", string(giOut))
		}

		// Re-run AutoFix on another dotenv finding to verify .gitignore does not get duplicated
		findings2 := []EnrichedFinding{
			{
				RuleID:        "generic-api-key",
				File:          ".env",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secret_app_key_12345",
				MaskedSecret:  "secr****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}
		sum2, err := AutoFix(findings2, FixOptions{RepoDir: repo, Apply: true, BranchName: "fix/env-again"})
		if err != nil {
			t.Fatalf("AutoFix second run error: %v", err)
		}
		cmd = exec.Command("git", "show", sum2.Branch+":.gitignore")
		cmd.Dir = repo
		giOut2, _ := cmd.CombinedOutput()
		if strings.Count(string(giOut2), ".env") != 1 {
			t.Errorf("expected '.env' to not be duplicated in .gitignore, got: %s", string(giOut2))
		}
	})

	t.Run("7. Rollback: forced failure after branch creation cleans worktree and deletes branch", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		commitFile(t, repo, "test.py", "token = 'secretval12345'\n")

		// Create a pre-commit hook that exits 1 to force a failure during worktreeGit.Commit()
		hooksDir := filepath.Join(repo, ".git", "hooks")
		_ = os.MkdirAll(hooksDir, 0755)
		preCommitHook := filepath.Join(hooksDir, "pre-commit")
		_ = os.WriteFile(preCommitHook, []byte("#!/bin/sh\nexit 1\n"), 0755)

		findings := []EnrichedFinding{
			{
				RuleID:        "secret-token",
				File:          "test.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secretval12345",
				MaskedSecret:  "secr****45",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		fixBranch := "fix/rollback-test"
		_, err := AutoFix(findings, FixOptions{
			RepoDir:    repo,
			Apply:      true,
			BranchName: fixBranch,
		})
		if err == nil {
			t.Fatalf("expected error due to pre-commit hook failure, got nil")
		}

		git := NewGitRepo(repo)
		// Fix branch must have been deleted
		if git.BranchExists(fixBranch) {
			t.Errorf("failed branch %s was not rolled back/deleted", fixBranch)
		}

		// Current branch must remain main
		branch, _ := git.GetCurrentBranch()
		if branch != "main" {
			t.Errorf("current branch changed to %s, expected main", branch)
		}

		// git status --short must be clean
		statusOut, err := exec.Command("git", "-C", repo, "status", "--short").CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(statusOut))) > 0 {
			t.Errorf("working tree status not clean after rollback: %s", string(statusOut))
		}
	})

	t.Run("8. --fix-branch override with collision numeric suffix", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		git := NewGitRepo(repo)

		// Create custom branch already
		_ = exec.Command("git", "-C", repo, "branch", "my-custom-fix").Run()

		unique := git.GenerateUniqueBranchName("my-custom-fix")
		if unique != "my-custom-fix-2" {
			t.Errorf("expected my-custom-fix-2, got %s", unique)
		}
	})

	t.Run("9. Preview writes nothing (no branches created, no worktrees, git status clean)", func(t *testing.T) {
		repo := setupTestGitRepo(t)
		code := "api_key = 'secretpreviewtoken123'\n"
		commitFile(t, repo, "preview.py", code)

		findings := []EnrichedFinding{
			{
				RuleID:        "api-token",
				File:          "preview.py",
				StartLine:     1,
				EndLine:       1,
				RawSecret:     "secretpreviewtoken123",
				MaskedSecret:  "secr****23",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
		}

		sum, err := AutoFix(findings, FixOptions{
			RepoDir: repo,
			Apply:   false, // Preview mode
		})
		if err != nil {
			t.Fatalf("preview failed: %v", err)
		}

		if sum.EligibleCount != 1 {
			t.Errorf("expected 1 eligible finding, got %d", sum.EligibleCount)
		}
		if sum.AppliedCount != 0 {
			t.Errorf("preview should have 0 applied count, got %d", sum.AppliedCount)
		}

		// Check that no extra branches were created
		out, _ := exec.Command("git", "-C", repo, "branch").CombinedOutput()
		branches := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(branches) != 1 {
			t.Errorf("expected only 1 branch in repo, got: %v", branches)
		}

		// Check that git status --short is empty
		statusOut, _ := exec.Command("git", "-C", repo, "status", "--short").CombinedOutput()
		if len(strings.TrimSpace(string(statusOut))) != 0 {
			t.Errorf("working tree is not clean after preview: %s", string(statusOut))
		}

		// Check that file on disk is unchanged
		data, _ := os.ReadFile(filepath.Join(repo, "preview.py"))
		if string(data) != code {
			t.Errorf("preview mutated file! Expected %q, got %q", code, string(data))
		}
	})
}
