package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// AllowlistOptions controls WriteSuggestedAllowlist.
type AllowlistOptions struct {
	OutputPath    string  // file to append to; created if missing
	MinConfidence float64 // defaults to 0.8 when <= 0
	DryRun        bool    // print only, write nothing
}

// AllowlistSummary reports what happened.
type AllowlistSummary struct {
	Added          int
	AlreadyPresent int
	Ineligible     int
	DryRun         bool
	OutputPath     string
}

func (s AllowlistSummary) String() string {
	mode := "written to " + s.OutputPath
	if s.DryRun {
		mode = "dry run, nothing written"
	}
	return fmt.Sprintf("=== ALLOWLIST (%s) ===\nAdded: %d\nAlready present: %d\nIneligible (not an LLM false positive at the confidence threshold): %d\n=======================\n",
		mode, s.Added, s.AlreadyPresent, s.Ineligible)
}

// allowlistEligible is deliberately strict: only an LLM verdict of
// likely_false_positive at or above the confidence threshold qualifies.
// Heuristic, real_secret, needs_review and untriaged findings never do.
func allowlistEligible(f EnrichedFinding, minConf float64) bool {
	if f.Triage == nil || f.Triage.Source != "llm" ||
		f.Triage.Verdict != "likely_false_positive" || f.Triage.Confidence < minConf {
		return false
	}
	fp := strings.TrimSpace(f.Fingerprint)
	return fp != "" && !strings.ContainsAny(fp, "\r\n") && !strings.HasPrefix(fp, "#")
}

// allowlistClean makes text safe for a one-line comment.
func allowlistClean(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ") // collapses CR, LF, tabs, line separators
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	cut := string(r[:max-3])
	if i := strings.LastIndex(cut, " "); i > max/2 {
		cut = cut[:i]
	}
	return cut + "..."
}

// WriteSuggestedAllowlist appends per-finding fingerprints (one per line) in the
// format Gitleaks expects, each preceded by a comment explaining why.
func WriteSuggestedAllowlist(findings []EnrichedFinding, opts AllowlistOptions) (AllowlistSummary, error) {
	if opts.MinConfidence <= 0 {
		opts.MinConfidence = 0.8
	}
	sum := AllowlistSummary{DryRun: opts.DryRun, OutputPath: opts.OutputPath}
	if opts.OutputPath == "" {
		return sum, fmt.Errorf("allowlist output path is empty")
	}

	existing := map[string]bool{}
	var existingRaw []byte
	if data, err := os.ReadFile(opts.OutputPath); err == nil {
		existingRaw = data
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				existing[line] = true
			}
		}
	} else if !os.IsNotExist(err) {
		return sum, err
	}

	var out strings.Builder
	for _, f := range findings {
		if !allowlistEligible(f, opts.MinConfidence) {
			sum.Ineligible++
			continue
		}
		fp := strings.TrimSpace(f.Fingerprint)
		if existing[fp] {
			sum.AlreadyPresent++
			continue
		}
		existing[fp] = true
		sum.Added++
		fmt.Fprintf(&out, "# SecretSentinel: %s %s - %s (confidence %.2f, llm)\n%s\n",
			allowlistClean(f.RuleID, 60), allowlistClean(f.File, 120),
			allowlistClean(f.Triage.Reason, 120), f.Triage.Confidence, fp)
	}

	if opts.DryRun {
		fmt.Println("DRY RUN - nothing written")
		fmt.Print(out.String())
		return sum, nil
	}
	if sum.Added == 0 {
		return sum, nil
	}

	if len(existingRaw) > 0 { // back up once, before the first modification
		bak := opts.OutputPath + ".bak"
		if _, err := os.Stat(bak); os.IsNotExist(err) {
			if err := os.WriteFile(bak, existingRaw, 0o600); err != nil {
				return sum, err
			}
		}
	}
	fh, err := os.OpenFile(opts.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return sum, err
	}
	defer fh.Close()
	if len(existingRaw) > 0 && existingRaw[len(existingRaw)-1] != '\n' {
		if _, err := fh.WriteString("\n"); err != nil {
			return sum, err
		}
	}
	_, err = fh.WriteString(out.String())
	return sum, err
}
