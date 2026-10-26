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

func ExtractContext(targetPath string, mode string, commit string, filePath string, targetLine int, contextLines int, secret string, maskedSecret string, includeRaw bool) []string {
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

	var context []string
	for i := start; i <= end; i++ {
		line := rawLines[i]
		if secret != "" && !includeRaw {
			line = strings.ReplaceAll(line, secret, maskedSecret)
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
