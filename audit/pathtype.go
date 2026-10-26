package audit

import (
	"path/filepath"
	"strings"
)

func DetectPathType(path string) string {
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))

	// 1. Test heuristic
	if strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "\\test\\") ||
		strings.HasPrefix(base, "test_") ||
		strings.HasSuffix(base, "_test.go") ||
		strings.Contains(lower, "spec/") ||
		strings.Contains(lower, "tests/") {
		return "test"
	}

	// 2. Example heuristic
	if strings.Contains(lower, "example") ||
		strings.Contains(lower, "sample") ||
		strings.Contains(lower, "demo") {
		return "example"
	}

	// 3. Docs heuristic
	if strings.Contains(lower, "doc") ||
		strings.HasSuffix(base, ".md") ||
		strings.HasSuffix(base, ".rst") ||
		strings.HasSuffix(base, ".txt") {
		return "docs"
	}

	// 4. Vendor heuristic
	if strings.Contains(lower, "vendor/") ||
		strings.Contains(lower, "vendor\\") ||
		strings.Contains(lower, "node_modules/") ||
		strings.Contains(lower, "node_modules\\") ||
		strings.Contains(lower, "third_party/") {
		return "vendor"
	}

	// 5. Config heuristic
	if strings.Contains(lower, "config/") ||
		strings.Contains(lower, "config\\") ||
		strings.HasPrefix(base, ".env") ||
		strings.HasSuffix(base, ".json") ||
		strings.HasSuffix(base, ".yml") ||
		strings.HasSuffix(base, ".yaml") ||
		strings.HasSuffix(base, ".toml") ||
		strings.HasSuffix(base, ".ini") ||
		strings.HasSuffix(base, ".xml") {
		return "config"
	}

	return "source"
}