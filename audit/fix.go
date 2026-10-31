package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FixOptions struct {
	RepoDir       string
	Apply         bool
	BranchName    string
	IncludeReview bool
}

type FindingFixStatus struct {
	Finding  EnrichedFinding
	Eligible bool
	Reason   string
	Action   string
	File     string
	EnvVar   string
	OldLine  string
	NewLine  string
	Diff     string
}

type FixSummary struct {
	EligibleCount   int
	AppliedCount    int
	SkippedCount    int
	Branch          string
	Statuses        []FindingFixStatus
	Warnings        []string
	RotationWarning string
}

func (s *FixSummary) String() string {
	var b strings.Builder
	if s.AppliedCount == 0 {
		b.WriteString("=== FIX PREVIEW - nothing written ===\n")
	} else {
		b.WriteString("=== FIX SUMMARY ===\n")
	}

	for _, st := range s.Statuses {
		if st.Eligible {
			b.WriteString(fmt.Sprintf("[ELIGIBLE] %s:%d (%s)\n", st.Finding.File, st.Finding.StartLine, st.Finding.RuleID))
			b.WriteString(fmt.Sprintf("  Action: %s\n", st.Action))
			if st.EnvVar != "" {
				b.WriteString(fmt.Sprintf("  Env Var: %s\n", st.EnvVar))
			}
			if st.OldLine != "" && st.NewLine != "" {
				b.WriteString(fmt.Sprintf("  - %s\n", strings.TrimSpace(st.OldLine)))
				b.WriteString(fmt.Sprintf("  + %s\n", strings.TrimSpace(st.NewLine)))
			}
		} else {
			b.WriteString(fmt.Sprintf("[SKIPPED] %s:%d (%s) - %s\n", st.Finding.File, st.Finding.StartLine, st.Finding.RuleID, st.Reason))
		}
	}

	b.WriteString("-------------------------------------\n")
	b.WriteString(fmt.Sprintf("Total Eligible: %d | Total Skipped: %d\n", s.EligibleCount, s.SkippedCount))
	if s.AppliedCount > 0 {
		b.WriteString(fmt.Sprintf("Changes committed to branch: %s\n", s.Branch))
		b.WriteString("Note: Fixes were applied in an isolated worktree based on committed state.\n")
	}
	if s.RotationWarning != "" {
		b.WriteString(fmt.Sprintf("\n%s\n", s.RotationWarning))
	}
	b.WriteString("=====================================\n")
	return b.String()
}

type fileWorkState struct {
	lines              []string
	crlf               bool
	hasTrailingNewline bool
}

// AutoFix processes findings and previews or applies fixes.
func AutoFix(findings []EnrichedFinding, opts FixOptions) (*FixSummary, error) {
	summary := &FixSummary{
		RotationWarning: "SECURITY WARNING: Existing credentials identified in code or commits must be rotated immediately. Auto-fix removes credentials from source files, but credentials may still remain in Git history or external logs.",
	}

	git := NewGitRepo(opts.RepoDir)
	if !git.IsGitRepo() {
		return nil, fmt.Errorf("target %s is not a valid git repository", opts.RepoDir)
	}

	// Map of existing env vars used per file
	fileEnvVars := make(map[string]map[string]bool)

	fileStates := make(map[string]*fileWorkState)
	fileOriginalPerms := make(map[string]os.FileMode)
	fileImportOsNeeded := make(map[string]bool)
	dotenvFilesToUntrack := make(map[string]bool)
	dotenvVarsToAdd := make(map[string]bool)

	// Evaluate eligibility
	for _, f := range findings {
		status := FindingFixStatus{
			Finding: f,
			File:    f.File,
		}

		// 1. Triage status check
		verdict := ""
		if f.Triage != nil {
			verdict = f.Triage.Verdict
		}
		if verdict != "real_secret" {
			if !(opts.IncludeReview && verdict == "needs_review") {
				status.Eligible = false
				status.Reason = "not a real_secret"
				summary.SkippedCount++
				summary.Statuses = append(summary.Statuses, status)
				continue
			}
		}

		// 2. Risk level check
		if f.RiskLevel == "info" {
			status.Eligible = false
			status.Reason = "risk level is info"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		// 3. In history only
		if f.InHistoryOnly {
			status.Eligible = false
			status.Reason = "history-only"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		// 4. Path traversal / absolute paths
		if filepath.IsAbs(f.File) || strings.HasPrefix(filepath.Clean(f.File), "..") {
			status.Eligible = false
			status.Reason = "invalid file path (traversal)"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		fullPath := filepath.Join(opts.RepoDir, f.File)
		// Check symlink safety
		if fi, err := os.Lstat(fullPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(fullPath)
			if err != nil || !strings.HasPrefix(filepath.Clean(target), filepath.Clean(opts.RepoDir)) {
				status.Eligible = false
				status.Reason = "symlink leaves repository"
				summary.SkippedCount++
				summary.Statuses = append(summary.Statuses, status)
				continue
			}
		}

		// 5. File exists on disk
		info, err := os.Stat(fullPath)
		if err != nil {
			status.Eligible = false
			status.Reason = "file does not exist in working tree"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}
		fileOriginalPerms[f.File] = info.Mode()

		// 6. Tracked by git
		if !git.IsTracked(f.File) {
			status.Eligible = false
			status.Reason = "untracked file"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		// 7. Multi-line secret check
		if f.StartLine != f.EndLine || strings.Contains(f.RawSecret, "\n") || f.RuleID == "private-key" {
			status.Eligible = false
			status.Reason = "multi-line secret"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		// 8. Language support check
		lang := DetectLanguage(f.File)
		if lang == LangUnknown {
			status.Eligible = false
			status.Reason = "unsupported language"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		// Load or retrieve file state
		state := fileStates[f.File]
		if state == nil {
			content, err := os.ReadFile(fullPath)
			if err != nil {
				status.Eligible = false
				status.Reason = "could not read file"
				summary.SkippedCount++
				summary.Statuses = append(summary.Statuses, status)
				continue
			}

			crlf := bytes.Contains(content, []byte("\r\n"))
			hasTrailingNewline := len(content) > 0 && (content[len(content)-1] == '\n' || content[len(content)-1] == '\r')

			rawLines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
			if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" && hasTrailingNewline {
				rawLines = rawLines[:len(rawLines)-1]
			}

			state = &fileWorkState{
				lines:              rawLines,
				crlf:               crlf,
				hasTrailingNewline: hasTrailingNewline,
			}
			fileStates[f.File] = state
		}

		if f.StartLine <= 0 || f.StartLine > len(state.lines) {
			status.Eligible = false
			status.Reason = "line out of range"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		targetLine := state.lines[f.StartLine-1]

		// Initialize env var tracking map for file
		if fileEnvVars[f.File] == nil {
			fileEnvVars[f.File] = make(map[string]bool)
		}
		envVar := DeriveSmartEnvVarName(targetLine, f.RawSecret, f.RuleID, lang, fileEnvVars[f.File])
		status.EnvVar = envVar

		if lang == LangDotenv {
			// Dotenv workflow
			status.Eligible = true
			status.Action = "Untrack from git, add to .gitignore, add key to .env.example"
			dotenvFilesToUntrack[f.File] = true
			dotenvVarsToAdd[envVar] = true
			summary.EligibleCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}
		if strings.Count(targetLine, f.RawSecret) != 1 {
			status.Eligible = false
			status.Reason = "raw secret not found exactly once on target line"
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		var newLine, reason string
		switch lang {
		case LangPython:
			newLine, reason = PatchPythonLine(targetLine, f.RawSecret, envVar)
		case LangJavaScript:
			newLine, reason = PatchJSLine(targetLine, f.RawSecret, envVar)
		}

		if reason != "" {
			status.Eligible = false
			status.Reason = reason
			summary.SkippedCount++
			summary.Statuses = append(summary.Statuses, status)
			continue
		}

		status.Eligible = true
		status.Action = fmt.Sprintf("Replace secret literal with environment variable %s", envVar)
		status.OldLine = targetLine
		status.NewLine = newLine
		summary.EligibleCount++
		summary.Statuses = append(summary.Statuses, status)

		// Apply line patch in current file state
		state.lines[f.StartLine-1] = newLine
		if lang == LangPython {
			fileImportOsNeeded[f.File] = true
		}
	}

	if !opts.Apply || summary.EligibleCount == 0 {
		return summary, nil
	}

	// Determine unique branch name
	branchName := git.GenerateUniqueBranchName(opts.BranchName)
	summary.Branch = branchName

	// Create temporary directory for worktree
	tempWorktreeDir, err := os.MkdirTemp("", "secretsentinel-worktree-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary worktree directory: %w", err)
	}

	branchCreated := false
	worktreeAdded := false

	defer func() {
		if worktreeAdded {
			_ = git.RemoveWorktree(tempWorktreeDir)
		}
		_ = os.RemoveAll(tempWorktreeDir)
	}()

	// Add worktree based on HEAD
	if err := git.AddWorktree(tempWorktreeDir, branchName); err != nil {
		return nil, fmt.Errorf("failed to create worktree on branch %s: %w", branchName, err)
	}
	worktreeAdded = true
	branchCreated = true

	rollbackBranch := func(errReason error) error {
		if worktreeAdded {
			_ = git.RemoveWorktree(tempWorktreeDir)
			worktreeAdded = false
		}
		if branchCreated {
			_ = git.DeleteBranch(branchName)
			branchCreated = false
		}
		return errReason
	}

	worktreeGit := NewGitRepo(tempWorktreeDir)
	var filesToStage []string

	// Write modified source files in worktree
	for relPath, state := range fileStates {
		if DetectLanguage(relPath) == LangDotenv {
			continue
		}
		lines := state.lines
		if fileImportOsNeeded[relPath] {
			lines = InsertPythonImportOS(lines)
		}

		var outBuf bytes.Buffer
		lineSep := "\n"
		if state.crlf {
			lineSep = "\r\n"
		}
		for i, l := range lines {
			outBuf.WriteString(l)
			if i < len(lines)-1 || state.hasTrailingNewline {
				outBuf.WriteString(lineSep)
			}
		}

		destPath := filepath.Join(tempWorktreeDir, relPath)
		perm := fileOriginalPerms[relPath]
		if perm == 0 {
			perm = 0644
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return nil, rollbackBranch(fmt.Errorf("failed to create directories for %s: %w", relPath, err))
		}
		if err := os.WriteFile(destPath, outBuf.Bytes(), perm); err != nil {
			return nil, rollbackBranch(fmt.Errorf("failed to write %s: %w", relPath, err))
		}
		filesToStage = append(filesToStage, relPath)
	}

	// Handle Dotenv files inside worktree
	for envFile := range dotenvFilesToUntrack {
		if err := worktreeGit.UntrackFile(envFile); err != nil {
			return nil, rollbackBranch(fmt.Errorf("failed to untrack %s in worktree: %w", envFile, err))
		}
	}

	if len(dotenvFilesToUntrack) > 0 {
		// Update .gitignore in worktree
		gitignorePath := filepath.Join(tempWorktreeDir, ".gitignore")
		var giContent string
		if d, err := os.ReadFile(gitignorePath); err == nil {
			giContent = string(d)
		}
		giLines := strings.Split(giContent, "\n")
		hasEnv := false
		for _, l := range giLines {
			if strings.TrimSpace(l) == ".env" {
				hasEnv = true
				break
			}
		}
		if !hasEnv {
			var newGI strings.Builder
			newGI.WriteString(giContent)
			if len(giContent) > 0 && !strings.HasSuffix(giContent, "\n") {
				newGI.WriteString("\n")
			}
			newGI.WriteString(".env\n")
			if err := os.WriteFile(gitignorePath, []byte(newGI.String()), 0644); err != nil {
				return nil, rollbackBranch(fmt.Errorf("failed to update .gitignore in worktree: %w", err))
			}
			filesToStage = append(filesToStage, ".gitignore")
		}

		// Update or create .env.example in worktree
		examplePath := filepath.Join(tempWorktreeDir, ".env.example")
		existingVars := make(map[string]bool)
		var exContent string
		if d, err := os.ReadFile(examplePath); err == nil {
			exContent = string(d)
			scanner := bufio.NewScanner(strings.NewReader(exContent))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.Contains(line, "=") {
					key := strings.SplitN(line, "=", 2)[0]
					existingVars[strings.TrimSpace(key)] = true
				}
			}
		}

		var newEx strings.Builder
		newEx.WriteString(exContent)
		if len(exContent) > 0 && !strings.HasSuffix(exContent, "\n") {
			newEx.WriteString("\n")
		}

		var sortedVars []string
		for v := range dotenvVarsToAdd {
			sortedVars = append(sortedVars, v)
		}
		sort.Strings(sortedVars)

		addedAny := false
		for _, v := range sortedVars {
			if !existingVars[v] {
				newEx.WriteString(fmt.Sprintf("%s=\n", v))
				addedAny = true
			}
		}
		if addedAny || len(exContent) == 0 {
			if err := os.WriteFile(examplePath, []byte(newEx.String()), 0644); err != nil {
				return nil, rollbackBranch(fmt.Errorf("failed to write .env.example in worktree: %w", err))
			}
			filesToStage = append(filesToStage, ".env.example")
		}
	}

	// Stage modified files in worktree
	stageMap := make(map[string]bool)
	var uniqueStage []string
	for _, f := range filesToStage {
		if !stageMap[f] {
			stageMap[f] = true
			uniqueStage = append(uniqueStage, f)
		}
	}

	if len(uniqueStage) > 0 {
		if err := worktreeGit.StageFiles(uniqueStage); err != nil {
			return nil, rollbackBranch(fmt.Errorf("failed to stage files in worktree: %w", err))
		}
	}

	// Build commit message with body listing file, rule ID, and env var name (NO SECRETS)
	var commitMsgBuilder strings.Builder
	commitMsgBuilder.WriteString(fmt.Sprintf("chore: remediate %d secret(s) via SecretSentinel auto-fix\n\n", summary.EligibleCount))
	commitMsgBuilder.WriteString("Remediated secrets replaced with environment variables:\n")
	for _, st := range summary.Statuses {
		if st.Eligible {
			if st.EnvVar != "" {
				commitMsgBuilder.WriteString(fmt.Sprintf("- %s (%s) -> %s\n", st.File, st.Finding.RuleID, st.EnvVar))
			} else {
				commitMsgBuilder.WriteString(fmt.Sprintf("- %s (%s)\n", st.File, st.Finding.RuleID))
			}
		}
	}
	commitMsgBuilder.WriteString("\nExisting credentials must be rotated immediately.")

	if err := worktreeGit.Commit(commitMsgBuilder.String()); err != nil {
		return nil, rollbackBranch(fmt.Errorf("failed to commit changes in worktree: %w", err))
	}

	summary.AppliedCount = summary.EligibleCount
	return summary, nil
}
