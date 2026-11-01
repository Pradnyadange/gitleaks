package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaybookAndPRDescription(t *testing.T) {
	t.Run("Provider detection mapping", func(t *testing.T) {
		tests := []struct {
			ruleID   string
			expected ProviderType
		}{
			{"github-pat", ProviderGitHub},
			{"github-fine-grained-pat", ProviderGitHub},
			{"aws-access-key", ProviderAWS},
			{"aws-secret-access-key", ProviderAWS},
			{"stripe-api-key", ProviderStripe},
			{"private-key", ProviderPrivateKey},
			{"generic-api-key", ProviderGeneric},
			{"custom-db-token", ProviderGeneric},
		}

		for _, tt := range tests {
			got := DetectProvider(tt.ruleID)
			if got != tt.expected {
				t.Errorf("DetectProvider(%q) = %q, want %q", tt.ruleID, got, tt.expected)
			}
		}
	})

	t.Run("Playbook structure: executive summary, present providers, omits absent, ignored count", func(t *testing.T) {
		findings := []EnrichedFinding{
			{
				RuleID:        "github-pat",
				File:          "src/auth.go",
				StartLine:     12,
				RawSecret:     "ghp_11111111111111111111",
				MaskedSecret:  "ghp_****11",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "high",
				InHistoryOnly: false,
			},
			{
				RuleID:        "aws-access-key",
				File:          "config/aws.go",
				StartLine:     5,
				RawSecret:     "AKIAIOSFODNN7EXAMPLE",
				MaskedSecret:  "AKIA****LE",
				Triage:        &Triage{Verdict: "real_secret"},
				RiskLevel:     "critical",
				InHistoryOnly: true, // history only
			},
			{
				RuleID:        "stripe-api-key",
				File:          "test/dummy.go",
				StartLine:     20,
				RawSecret:     "sk_test_fakefakefakefake",
				MaskedSecret:  "sk_t****ke",
				Triage:        &Triage{Verdict: "likely_false_positive"}, // should be omitted
				RiskLevel:     "info",
				InHistoryOnly: false,
			},
		}

		md := GeneratePlaybook(findings)

		// Executive summary table
		if !strings.Contains(md, "## Executive Summary") {
			t.Errorf("expected executive summary table in playbook")
		}
		if !strings.Contains(md, "| GitHub | 1 | HIGH |") {
			t.Errorf("expected GitHub entry in executive summary")
		}
		if !strings.Contains(md, "| Amazon Web Services (AWS) | 1 | CRITICAL |") {
			t.Errorf("expected AWS entry in executive summary")
		}

		// Ignored count
		if !strings.Contains(md, "Ignored: 1") {
			t.Errorf("expected 'Ignored: 1' count in playbook, got: %s", md)
		}

		// Present providers
		if !strings.Contains(md, "## GitHub Rotation Procedure") {
			t.Errorf("expected GitHub rotation procedure")
		}
		if !strings.Contains(md, "## Amazon Web Services (AWS) Rotation Procedure") {
			t.Errorf("expected AWS rotation procedure")
		}

		// Step order
		if !strings.Contains(md, "### Step 1: Create New Credential") ||
			!strings.Contains(md, "### Step 2: Deploy New Credential") ||
			!strings.Contains(md, "### Step 3: Revoke Compromised Credential") ||
			!strings.Contains(md, "### Step 4: Audit & Verify") {
			t.Errorf("expected step order 1:Create, 2:Deploy, 3:Revoke, 4:Audit")
		}

		// Current documentation note
		if !strings.Contains(md, "Verify these steps against the provider's current documentation.") {
			t.Errorf("expected current documentation note")
		}

		// Immediate revocation warning note
		if !strings.Contains(md, "If the credential may already be abused, revoke it immediately and accept the downtime") {
			t.Errorf("expected immediate revocation note")
		}

		// Absent provider
		if strings.Contains(md, "Stripe Rotation Procedure") {
			t.Errorf("Stripe was likely_false_positive and should be omitted from playbooks")
		}
		if strings.Contains(md, "SSH / TLS Private Key Rotation Procedure") {
			t.Errorf("SSH private key was absent and should be omitted from playbooks")
		}

		// History section
		if !strings.Contains(md, "## Git History & Remediation") {
			t.Errorf("expected Git history section in playbook")
		}

		// Status column in inventory table without fix summary
		if !strings.Contains(md, "History only: rotate the key") {
			t.Errorf("expected 'History only: rotate the key' in inventory table")
		}
		if !strings.Contains(md, "Not fixed in this run") {
			t.Errorf("expected 'Not fixed in this run' when no fix summary provided")
		}
	})

	t.Run("Playbook inventory reflects fix engine status", func(t *testing.T) {
		f1 := EnrichedFinding{
			RuleID:       "github-pat",
			File:         "src/auth.go",
			StartLine:    12,
			MaskedSecret: "ghp_****11",
			Triage:       &Triage{Verdict: "real_secret"},
		}
		f2 := EnrichedFinding{
			RuleID:       "custom-key",
			File:         "src/key.go",
			StartLine:    5,
			MaskedSecret: "cust****55",
			Triage:       &Triage{Verdict: "real_secret"},
		}

		fixSum := &FixSummary{
			AppliedCount: 1,
			Branch:       "secretsentinel/fix-20261101",
			Statuses: []FindingFixStatus{
				{
					Finding:  f1,
					Eligible: true,
					File:     f1.File,
					EnvVar:   "GITHUB_TOKEN",
				},
				{
					Finding:  f2,
					Eligible: false,
					File:     f2.File,
					Reason:   "embedded in a larger string",
				},
			},
		}

		md := GeneratePlaybook([]EnrichedFinding{f1, f2}, PlaybookOptions{FixSummary: fixSum})

		if !strings.Contains(md, "Fixed on branch secretsentinel/fix-20261101") {
			t.Errorf("expected fixed on branch status for f1")
		}
		if !strings.Contains(md, "Manual fix needed") {
			t.Errorf("expected Manual fix needed status for f2")
		}
	})

	t.Run("PR description: unified env vars and remediation table restriction", func(t *testing.T) {
		// Test finding where rule ID is "rule-api-token" but line has "customApiKey = ..." -> "CUSTOM_API_KEY"
		fEligible := EnrichedFinding{
			RuleID:        "rule-api-token",
			File:          "src/auth.js",
			StartLine:     3,
			RawSecret:     "secrettoken123456",
			MaskedSecret:  "secr****56",
			Triage:        &Triage{Verdict: "real_secret"},
			InHistoryOnly: false,
		}
		fHistory := EnrichedFinding{
			RuleID:        "aws-key",
			File:          "old.py",
			StartLine:     1,
			RawSecret:     "AKIAIOSFODNN7EXAMPLE",
			MaskedSecret:  "AKIA****LE",
			Triage:        &Triage{Verdict: "real_secret"},
			InHistoryOnly: true, // history only
		}
		fSkipped := EnrichedFinding{
			RuleID:        "db-conn",
			File:          "db.go",
			StartLine:     10,
			RawSecret:     "pass123456",
			MaskedSecret:  "pass****56",
			Triage:        &Triage{Verdict: "real_secret"},
			InHistoryOnly: false,
		}

		fixSum := &FixSummary{
			AppliedCount: 1,
			Branch:       "secretsentinel/remediation",
			Statuses: []FindingFixStatus{
				{
					Finding:  fEligible,
					Eligible: true,
					File:     fEligible.File,
					EnvVar:   "CUSTOM_API_KEY", // Extracted name from assignment
				},
				{
					Finding:  fHistory,
					Eligible: false,
					File:     fHistory.File,
					Reason:   "history-only",
				},
				{
					Finding:  fSkipped,
					Eligible: false,
					File:     fSkipped.File,
					Reason:   "embedded in a larger string",
				},
			},
		}

		pr := GeneratePRDescription([]EnrichedFinding{fEligible, fHistory, fSkipped}, PlaybookOptions{FixSummary: fixSum})

		// Should contain CUSTOM_API_KEY
		if !strings.Contains(pr, "`CUSTOM_API_KEY`") {
			t.Errorf("expected extracted env var `CUSTOM_API_KEY` in PR description, got:\n%s", pr)
		}
		// Must NOT contain rule ID fallback RULE_API_TOKEN
		if strings.Contains(pr, "`RULE_API_TOKEN`") {
			t.Errorf("unexpected fallback env var `RULE_API_TOKEN` in PR description")
		}

		// History-only finding must NEVER appear in remediation table
		if strings.Contains(pr, "`old.py`") || strings.Contains(pr, "aws-key") {
			t.Errorf("history-only finding appeared in remediation table:\n%s", pr)
		}

		// Skipped finding must NEVER appear in remediation table
		if strings.Contains(pr, "`db.go`") {
			t.Errorf("skipped finding appeared in remediation table:\n%s", pr)
		}

		// Diff note
		if !strings.Contains(pr, "The Git diff shows old exposed credential values on removed lines") {
			t.Errorf("expected note about Git diff in PR description")
		}

		// What this does not do section
		if !strings.Contains(pr, "### What This Does Not Do") {
			t.Errorf("expected 'What This Does Not Do' section in PR description")
		}
	})

	t.Run("PR description: without --apply-fix shows not fixed in this run and no env vars", func(t *testing.T) {
		f := EnrichedFinding{
			RuleID:       "github-pat",
			File:         "auth.go",
			StartLine:    1,
			RawSecret:    "ghp_1234567890",
			MaskedSecret: "ghp_****90",
			Triage:       &Triage{Verdict: "real_secret"},
		}

		// No FixSummary or AppliedCount == 0
		pr := GeneratePRDescription([]EnrichedFinding{f})

		if !strings.Contains(pr, "Status: Not fixed in this run") {
			t.Errorf("expected 'Status: Not fixed in this run' without apply-fix, got:\n%s", pr)
		}
		if strings.Contains(pr, "### Required Environment Variables") {
			t.Errorf("should not list required environment variables when nothing was fixed")
		}
	})

	t.Run("Markdown injection defense: backticks, pipes, newlines, angle brackets, leading hashes safely escaped", func(t *testing.T) {
		findings := []EnrichedFinding{
			{
				RuleID:        "### evil-rule | inject\nnewline <script>",
				File:          "path/`inject`.go\nnew_line",
				StartLine:     1,
				RawSecret:     "secret12345",
				MaskedSecret:  "secr****45 | pipe `evil` <tag>",
				Triage:        &Triage{Verdict: "real_secret"},
				InHistoryOnly: false,
			},
		}

		md := GeneratePlaybook(findings)

		if strings.Contains(md, "inject\nnewline") {
			t.Errorf("raw newline was not stripped/escaped from table cell")
		}
		if strings.Contains(md, "evil-rule | inject") {
			t.Errorf("pipe was not escaped in rule ID")
		}
		if !strings.Contains(md, "\\|") {
			t.Errorf("expected escaped pipe in table")
		}
		if strings.Contains(md, "<script>") || strings.Contains(md, "<tag>") {
			t.Errorf("angle brackets not escaped")
		}
		if strings.Contains(md, "### evil-rule") {
			t.Errorf("leading hash was not escaped")
		}
	})

	t.Run("Absolute absence of raw secrets in playbook and PR description", func(t *testing.T) {
		rawKey := "SUPER_SECRET_RAW_TOKEN_99999"
		findings := []EnrichedFinding{
			{
				RuleID:        "custom-key",
				File:          "app.py",
				StartLine:     1,
				RawSecret:     rawKey,
				MaskedSecret:  "SUPE****99",
				Triage:        &Triage{Verdict: "real_secret"},
				InHistoryOnly: false,
			},
		}

		playbook := GeneratePlaybook(findings)
		if strings.Contains(playbook, rawKey) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: raw secret present in playbook:\n%s", playbook)
		}

		prDesc := GeneratePRDescription(findings)
		if strings.Contains(prDesc, rawKey) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: raw secret present in PR description:\n%s", prDesc)
		}
	})

	t.Run("Zero findings behavior", func(t *testing.T) {
		pb := GeneratePlaybook(nil)
		if !strings.Contains(pb, "No active credential leaks") {
			t.Errorf("expected friendly zero findings message in playbook, got: %s", pb)
		}

		pr := GeneratePRDescription(nil)
		if !strings.Contains(pr, "No credentials were automatically remediated") {
			t.Errorf("expected friendly zero findings message in PR description, got: %s", pr)
		}
	})

	t.Run("File writer helpers create files with options", func(t *testing.T) {
		tmpDir := t.TempDir()
		pbPath := filepath.Join(tmpDir, "docs", "PLAYBOOK.md")
		prPath := filepath.Join(tmpDir, "docs", "PR.md")

		findings := []EnrichedFinding{
			{
				RuleID:        "aws-key",
				File:          "aws.py",
				StartLine:     1,
				RawSecret:     "AKIAIOSFODNN7EXAMPLE",
				MaskedSecret:  "AKIA****LE",
				Triage:        &Triage{Verdict: "real_secret"},
				InHistoryOnly: false,
			},
		}

		opts := PlaybookOptions{
			FixSummary: &FixSummary{
				AppliedCount: 1,
				Branch:       "fix/aws-key",
				Statuses: []FindingFixStatus{
					{
						Finding:  findings[0],
						Eligible: true,
						File:     "aws.py",
						EnvVar:   "AWS_ACCESS_KEY",
					},
				},
			},
		}

		if err := WritePlaybookFile(findings, pbPath, opts); err != nil {
			t.Fatalf("WritePlaybookFile failed: %v", err)
		}
		if err := WritePRDescriptionFile(findings, prPath, opts); err != nil {
			t.Fatalf("WritePRDescriptionFile failed: %v", err)
		}

		if _, err := os.Stat(pbPath); err != nil {
			t.Errorf("playbook file not found: %v", err)
		}
		if _, err := os.Stat(prPath); err != nil {
			t.Errorf("PR file not found: %v", err)
		}
	})
}
