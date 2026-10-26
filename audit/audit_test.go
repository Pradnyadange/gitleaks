package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"short", "*****"},
		{"123456789", "*********"},
		{"abcdefghijk12345", "abcd****45"},
	}

	for _, tt := range tests {
		got := MaskSecret(tt.input)
		if got != tt.expected {
			t.Errorf("MaskSecret(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDetectPathType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"pkg/auth/test_login.go", "test"},
		{"tests/integration_spec.rb", "test"},
		{"examples/demo.py", "example"},
		{"docs/guide.md", "docs"},
		{"node_modules/foo/index.js", "vendor"},
		{"config/settings.toml", "config"},
		{".env.local", "config"},
		{"src/main.go", "source"},
	}

	for _, tt := range tests {
		got := DetectPathType(tt.path)
		if got != tt.expected {
			t.Errorf("DetectPathType(%q) = %q; want %q", tt.path, got, tt.expected)
		}
	}
}

func TestExtractContext(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sample.txt")
	secretVal := "SECRET_KEY=abc123456789xyz"
	content := "line1\nline2 " + secretVal + " line3\nline4\n"
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	t.Run("Normal context extraction with masking", func(t *testing.T) {
		masked := MaskSecret(secretVal)
		ctx := ExtractContext(tmpDir, "dir", "", "sample.txt", 2, 1, secretVal, masked, false)
		if len(ctx) != 3 {
			t.Fatalf("expected 3 lines of context, got %d", len(ctx))
		}
		if ctx[0] != "line1" || ctx[2] != "line4" {
			t.Errorf("unexpected surrounding lines: %v", ctx)
		}
		expectedLine2 := "line2 SECR****yz line3" // Corrected from SECE to SECR
		if ctx[1] != expectedLine2 {
			t.Errorf("expected masked line %q, got %q", expectedLine2, ctx[1])
		}
	})

	t.Run("Edge case line 1", func(t *testing.T) {
		ctx := ExtractContext(tmpDir, "dir", "", "sample.txt", 1, 2, "", "", false)
		if len(ctx) != 3 {
			t.Fatalf("expected 3 lines, got %d", len(ctx))
		}
	})

	t.Run("Missing file fallback", func(t *testing.T) {
		ctx := ExtractContext(tmpDir, "dir", "", "nonexistent.txt", 1, 2, "", "", false)
		if len(ctx) != 0 {
			t.Errorf("expected empty context for missing file, got %v", ctx)
		}
	})
}
