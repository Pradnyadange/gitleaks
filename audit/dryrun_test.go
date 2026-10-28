package audit

import (
	"io"
	"os"
	"strings"
	"testing"
)

func dryRunCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		_ = r.Close()
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func dryRunFixtures(n int) []EnrichedFinding {
	out := make([]EnrichedFinding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, EnrichedFinding{
			Fingerprint:  "abc:config.py:github-pat:" + string(rune('1'+i)),
			RuleID:       "github-pat",
			File:         "config.py",
			PathType:     "source",
			MaskedSecret: "ghp_****xx",
			SecretLength: 40,
			CodeContext:  []string{`TOKEN = "ghp_****xx"`},
		})
	}
	return out
}

func TestDryRunTriage(t *testing.T) {
	tempParent := os.TempDir()
	dir, err := os.MkdirTemp(tempParent, "dryrun-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(tempParent)
		_ = os.RemoveAll(dir)
	}()

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	t.Run("prints label, system prompt, and one user prompt per finding", func(t *testing.T) {
		var stats TriageStats
		out := dryRunCaptureStdout(t, func() {
			_, stats = DryRunTriage(dryRunFixtures(3), TriageOptions{MaxFindings: 50})
		})
		if !strings.Contains(out, "DRY RUN - nothing sent") {
			t.Fatal("missing DRY RUN label")
		}
		if !strings.Contains(out, "--- SYSTEM PROMPT ---") {
			t.Fatal("missing system prompt")
		}
		if got := strings.Count(out, "--- USER PROMPT"); got != 3 {
			t.Fatalf("want 3 user prompts, got %d", got)
		}
		if !strings.Contains(out, "ghp_****xx") {
			t.Fatal("masked value missing from prompt")
		}
		if stats.APICalls != 0 {
			t.Fatalf("dry run must make 0 API calls, got %d", stats.APICalls)
		}
	})

	t.Run("respects MaxFindings", func(t *testing.T) {
		out := dryRunCaptureStdout(t, func() {
			DryRunTriage(dryRunFixtures(5), TriageOptions{MaxFindings: 2})
		})
		if got := strings.Count(out, "--- USER PROMPT"); got != 2 {
			t.Fatalf("want 2 user prompts, got %d", got)
		}
	})

	t.Run("does not read or write the cache", func(t *testing.T) {
		dryRunCaptureStdout(t, func() {
			DryRunTriage(dryRunFixtures(2), TriageOptions{MaxFindings: 50})
		})
		if _, err := os.Stat(CacheFilename); !os.IsNotExist(err) {
			t.Fatal("dry run created or touched the cache file")
		}
	})

	t.Run("findings get heuristic placeholders, never llm", func(t *testing.T) {
		var res []EnrichedFinding
		dryRunCaptureStdout(t, func() {
			res, _ = DryRunTriage(dryRunFixtures(2), TriageOptions{MaxFindings: 50})
		})
		for _, f := range res {
			if f.Triage == nil || f.Triage.Source != "heuristic" || f.Triage.Verdict == "real_secret" {
				t.Fatalf("unexpected triage in dry run: %+v", f.Triage)
			}
		}
	})
}
