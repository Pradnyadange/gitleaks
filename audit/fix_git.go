package audit

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type GitRepo struct {
	Dir string
}

func NewGitRepo(dir string) *GitRepo {
	return &GitRepo{Dir: dir}
}

func (g *GitRepo) run(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if g.Dir != "" {
		cmd.Dir = g.Dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// IsGitRepo checks if dir is a valid git repository
func (g *GitRepo) IsGitRepo() bool {
	_, err := g.run("rev-parse", "--is-inside-work-tree")
	return err == nil
}

// GetCurrentBranch returns active branch name or SHA
func (g *GitRepo) GetCurrentBranch() (string, error) {
	out, err := g.run("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return out, nil
}

// IsClean checks if there are uncommitted changes to tracked files
func (g *GitRepo) IsClean() (bool, error) {
	out, err := g.run("status", "--porcelain", "-uno")
	if err != nil {
		return false, err
	}
	return len(strings.TrimSpace(out)) == 0, nil
}

// IsTracked checks if a file is tracked in git index
func (g *GitRepo) IsTracked(relPath string) bool {
	_, err := g.run("ls-files", "--error-unmatch", relPath)
	return err == nil
}

// BranchExists checks if a local or remote tracking branch exists
func (g *GitRepo) BranchExists(branchName string) bool {
	// Check local heads
	if _, err := g.run("rev-parse", "--verify", "refs/heads/"+branchName); err == nil {
		return true
	}
	// Check via git branch --list
	out, err := g.run("branch", "--list", branchName)
	if err == nil && len(strings.TrimSpace(out)) > 0 {
		return true
	}
	// Check remote branches if any
	outRemote, err := g.run("branch", "-r", "--list", "*/"+branchName)
	if err == nil && len(strings.TrimSpace(outRemote)) > 0 {
		return true
	}
	return false
}

// GenerateUniqueBranchName generates a unique branch name like secretsentinel/fix-YYYYMMDD-HHMM
// or suffixes -2, -3, etc. if the branch name (provided or default) already exists.
func (g *GitRepo) GenerateUniqueBranchName(baseName string) string {
	if baseName == "" {
		now := time.Now().Format("20060102-1504")
		baseName = fmt.Sprintf("secretsentinel/fix-%s", now)
	}

	candidate := baseName
	counter := 2
	for g.BranchExists(candidate) {
		candidate = fmt.Sprintf("%s-%d", baseName, counter)
		counter++
	}
	return candidate
}

// AddWorktree creates a new worktree at tempDir on branch branchName based on HEAD
func (g *GitRepo) AddWorktree(tempDir, branchName string) error {
	_, err := g.run("worktree", "add", "-b", branchName, tempDir, "HEAD")
	return err
}

// RemoveWorktree deletes the worktree registration and folder
func (g *GitRepo) RemoveWorktree(tempDir string) error {
	_, err := g.run("worktree", "remove", "--force", tempDir)
	return err
}

// DeleteBranch deletes a branch forcibly
func (g *GitRepo) DeleteBranch(branchName string) error {
	_, err := g.run("branch", "-D", branchName)
	return err
}

// StageFiles stages individual files inside this repo/worktree
func (g *GitRepo) StageFiles(files []string) error {
	for _, f := range files {
		_, err := g.run("add", f)
		if err != nil {
			return err
		}
	}
	return nil
}

// UntrackFile runs git rm -q inside this repo/worktree
func (g *GitRepo) UntrackFile(relPath string) error {
	_, err := g.run("rm", "-q", relPath)
	return err
}

// Commit creates a commit with the specified message inside this repo/worktree
func (g *GitRepo) Commit(message string) error {
	_, err := g.run("-c", "user.name=SecretSentinel", "-c", "user.email=secretsentinel@gitleaks.io", "commit", "-m", message)
	return err
}
