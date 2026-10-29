package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func alFinding(fp, verdict, source string, conf float64, reason string) EnrichedFinding {
	return EnrichedFinding{
		Fingerprint: fp,
		RuleID:      "github-pat",
		File:        "tests/x.py",
		Triage:      &Triage{Verdict: verdict, Confidence: conf, Reason: reason, Source: source},
	}
}

func alRead(t *testing.T, path string) (fps []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			fps = append(fps, l)
		}
	}
	return fps
}

func TestWriteSuggestedAllowlist(t *testing.T) {
	t.Run("only high-confidence LLM false positives are written", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		findings := []EnrichedFinding{
			alFinding("A", "likely_false_positive", "llm", 0.9, "placeholder"),
			alFinding("B", "likely_false_positive", "heuristic", 0.9, "test path"),
			alFinding("C", "real_secret", "llm", 0.95, "real"),
			alFinding("D", "needs_review", "llm", 0.9, "unsure"),
			alFinding("E", "likely_false_positive", "llm", 0.5, "low confidence"),
			{Fingerprint: "F"},
		}
		sum, err := WriteSuggestedAllowlist(findings, AllowlistOptions{OutputPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if got := alRead(t, p); len(got) != 1 || got[0] != "A" {
			t.Fatalf("want only A, got %v", got)
		}
		if sum.Added != 1 || sum.Ineligible != 5 {
			t.Fatalf("unexpected summary: %+v", sum)
		}
	})

	t.Run("reason with newline cannot inject a line", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		evil := "ok\nSTOLEN:abc:github-pat:1\r\n# x"
		_, err := WriteSuggestedAllowlist(
			[]EnrichedFinding{alFinding("fpA", "likely_false_positive", "llm", 0.9, evil)},
			AllowlistOptions{OutputPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if got := alRead(t, p); len(got) != 1 || got[0] != "fpA" {
			t.Fatalf("injection leaked into entries: %v", got)
		}
	})

	t.Run("dedupes against existing entries and within the batch", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		if err := os.WriteFile(p, []byte("# old\nfpA\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sum, err := WriteSuggestedAllowlist([]EnrichedFinding{
			alFinding("fpA", "likely_false_positive", "llm", 0.9, "r"),
			alFinding("fpA", "likely_false_positive", "llm", 0.9, "r"),
			alFinding("fpB", "likely_false_positive", "llm", 0.9, "r"),
		}, AllowlistOptions{OutputPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if sum.Added != 1 || sum.AlreadyPresent != 2 {
			t.Fatalf("unexpected summary: %+v", sum)
		}
		if got := alRead(t, p); len(got) != 2 {
			t.Fatalf("want fpA and fpB once each, got %v", got)
		}
	})

	t.Run("backup is created and a missing trailing newline is handled", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		if err := os.WriteFile(p, []byte("fpOld"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := WriteSuggestedAllowlist(
			[]EnrichedFinding{alFinding("fpA", "likely_false_positive", "llm", 0.9, "r")},
			AllowlistOptions{OutputPath: p})
		if err != nil {
			t.Fatal(err)
		}
		bak, err := os.ReadFile(p + ".bak")
		if err != nil || string(bak) != "fpOld" {
			t.Fatalf("backup missing or wrong: %q %v", bak, err)
		}
		if got := alRead(t, p); len(got) != 2 || got[0] != "fpOld" || got[1] != "fpA" {
			t.Fatalf("fpOld and fpA must be on separate lines, got %v", got)
		}
	})

	t.Run("dry run writes nothing", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		sum, err := WriteSuggestedAllowlist(
			[]EnrichedFinding{alFinding("fpA", "likely_false_positive", "llm", 0.9, "r")},
			AllowlistOptions{OutputPath: p, DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatal("dry run created a file")
		}
		if sum.Added != 1 {
			t.Fatalf("dry run should still report 1 pending entry, got %+v", sum)
		}
	})

	t.Run("no file is created when nothing is eligible", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".gitleaksignore")
		_, err := WriteSuggestedAllowlist(
			[]EnrichedFinding{alFinding("fpA", "real_secret", "llm", 0.99, "r")},
			AllowlistOptions{OutputPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatal("file created without eligible findings")
		}
	})
}
