package audit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// FileFindingRef holds information about a finding in the same file to enable multi-secret redaction.
type FileFindingRef struct {
	StartLine    int
	EndLine      int
	Secret       string
	MaskedSecret string
	RuleID       string
}

func ExtractContext(targetPath string, mode string, commit string, filePath string, targetLine int, contextLines int, secret string, maskedSecret string, includeRaw bool, ruleIDOpt ...string) []string {
	return ExtractContextWithNeighbors(targetPath, mode, commit, filePath, targetLine, contextLines, secret, maskedSecret, includeRaw, nil, ruleIDOpt...)
}

func ExtractContextWithNeighbors(targetPath string, mode string, commit string, filePath string, targetLine int, contextLines int, secret string, maskedSecret string, includeRaw bool, neighbors []FileFindingRef, ruleIDOpt ...string) []string {
	ruleID := ""
	if len(ruleIDOpt) > 0 {
		ruleID = ruleIDOpt[0]
	}

	if targetLine <= 0 {
		targetLine = 1
	}

	var rawLines []string
	var err error

	if mode == "git" && commit != "" {
		rawLines, err = fetchGitCommitFileLines(targetPath, commit, filePath)
		if err != nil {
			log.Debug().Err(err).Msgf("failed to read file from git commit %s:%s, falling back to disk", commit, filePath)
		}
	}

	if len(rawLines) == 0 {
		diskPath := filePath
		// Check if filePath exists directly, otherwise try joining with targetPath or resolving relative paths
		if _, statErr := os.Stat(diskPath); os.IsNotExist(statErr) && targetPath != "" && !filepath.IsAbs(filePath) {
			joined := filepath.Join(targetPath, filePath)
			if _, statErr2 := os.Stat(joined); statErr2 == nil {
				diskPath = joined
			} else {
				// Handle case where filePath already contains targetPath prefix
				cleanTarget := filepath.Clean(targetPath)
				if strings.HasPrefix(filepath.Clean(filePath), cleanTarget) {
					diskPath = filePath
				}
			}
		}

		rawLines, err = fetchDiskFileLines(diskPath)
		if err != nil {
			log.Warn().Err(err).Msgf("could not retrieve file context for %s", filePath)
			return []string{}
		}
	}

	if len(rawLines) == 0 {
		return []string{}
	}

	start := targetLine - 1 - contextLines
	if start < 0 {
		start = 0
	}
	end := targetLine - 1 + contextLines
	if end >= len(rawLines) {
		end = len(rawLines) - 1
	}

	// Prepare list of all secrets to redact for this file
	type targetSecret struct {
		startLine    int
		secret       string
		maskedSecret string
		ruleID       string
		isMultiLine  bool
	}

	var allSecrets []targetSecret
	// Add primary finding secret
	isPrimaryMulti := strings.Contains(secret, "\n") || strings.Contains(secret, "PRIVATE KEY") || ruleID == "private-key"
	if secret != "" {
		allSecrets = append(allSecrets, targetSecret{
			startLine:    targetLine,
			secret:       secret,
			maskedSecret: maskedSecret,
			ruleID:       ruleID,
			isMultiLine:  isPrimaryMulti,
		})
	}

	// Add neighbor secrets from the same file
	for _, n := range neighbors {
		if n.Secret == "" || n.Secret == secret {
			continue
		}
		isNeighborMulti := strings.Contains(n.Secret, "\n") || strings.Contains(n.Secret, "PRIVATE KEY") || n.RuleID == "private-key" || (n.EndLine > n.StartLine && n.StartLine > 0)
		ms := n.MaskedSecret
		if ms == "" {
			ms = MaskSecret(n.Secret)
		}
		allSecrets = append(allSecrets, targetSecret{
			startLine:    n.StartLine,
			secret:       n.Secret,
			maskedSecret: ms,
			ruleID:       n.RuleID,
			isMultiLine:  isNeighborMulti,
		})
	}

	var context []string
	redactedPrintedForLine := make(map[int]bool)

	for i := start; i <= end; i++ {
		lineNum := i + 1
		line := rawLines[i]

		if !includeRaw {
			// Check multi-line secrets first
			isRedacted := false
			for _, s := range allSecrets {
				if s.isMultiLine {
					secretLineCount := strings.Count(s.secret, "\n")
					if lineNum >= s.startLine && lineNum <= s.startLine+secretLineCount {
						if !redactedPrintedForLine[lineNum] {
							context = append(context, "[REDACTED MULTI-LINE SECRET]")
							redactedPrintedForLine[lineNum] = true
						}
						isRedacted = true
						break
					}

					// Belt and braces check for lines containing secret parts
					hasPart := false
					for _, part := range strings.Split(s.secret, "\n") {
						trimmed := strings.TrimSpace(part)
						if len(trimmed) > 4 && strings.Contains(line, trimmed) {
							hasPart = true
							break
						}
					}
					if hasPart {
						if !redactedPrintedForLine[lineNum] {
							context = append(context, "[REDACTED MULTI-LINE SECRET]")
							redactedPrintedForLine[lineNum] = true
						}
						isRedacted = true
						break
					}
				}
			}

			if isRedacted {
				continue
			}

			// Redact/mask single line secrets (target and neighbors)
			for _, s := range allSecrets {
				if !s.isMultiLine && s.secret != "" {
					line = strings.ReplaceAll(line, s.secret, s.maskedSecret)
				}
			}
		}

		context = append(context, line)
	}

	return context
}

func fetchDiskFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func fetchGitCommitFileLines(repoPath string, commit string, filePath string) ([]string, error) {
	cmdArgs := []string{"show", fmt.Sprintf("%s:%s", commit, filePath)}
	cmd := exec.Command("git", cmdArgs...)
	if repoPath != "" {
		cmd.Dir = repoPath
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func IsInHistoryOnly(repoPath string, filePath string) bool {
	if repoPath == "" || filePath == "" {
		return false
	}
	fullPath := filePath
	if _, err := os.Stat(fullPath); os.IsNotExist(err) && !filepath.IsAbs(filePath) {
		joined := filepath.Join(repoPath, filePath)
		if _, err2 := os.Stat(joined); err2 == nil {
			return false
		}
	}
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return true
	}
	return false
}
