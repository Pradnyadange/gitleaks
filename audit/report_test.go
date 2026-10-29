package audit

import (
	"strings"
	"testing"
)

func TestReportGenerationAndSorting(t *testing.T) {
	findings := []EnrichedFinding{
		{
			RuleID:       "rule-low",
			File:         "demo.py",
			RiskScore:    10,
			RiskLevel:    "info",
			MaskedSecret: "SK_LOW****",
			Triage:       &Triage{Verdict: "likely_false_positive", Source: "llm", Reason: "Safe demo"},
		},
		{
			RuleID:       "rule-high",
			File:         "config.json",
			RiskScore:    95,
			RiskLevel:    "critical",
			MaskedSecret: "SK_HIGH****",
			CodeContext:  []string{"<script>alert(1)</script>", "API_KEY=SK_HIGH****"},
			Triage:       &Triage{Verdict: "real_secret", Source: "llm", Reason: "Exposed live key"},
		},
		{
			RuleID:       "rule-med",
			File:         "main.go",
			RiskScore:    50,
			RiskLevel:    "medium",
			MaskedSecret: "SK_MED****",
			Triage:       nil,
		},
	}

	t.Run("findings sorted by risk score descending with SortFindingsByScore", func(t *testing.T) {
		sorted := make([]EnrichedFinding, len(findings))
		copy(sorted, findings)
		SortFindingsByScore(sorted)

		if sorted[0].RiskScore < sorted[1].RiskScore || sorted[1].RiskScore < sorted[2].RiskScore {
			t.Errorf("findings not sorted in descending order of risk score: %d, %d, %d", sorted[0].RiskScore, sorted[1].RiskScore, sorted[2].RiskScore)
		}
	})

	t.Run("html escaping xss and asserting escaped form", func(t *testing.T) {
		html := GenerateReport(findings, "html")
		if strings.Contains(html, "<script>alert(1)</script>") {
			t.Errorf("HTML report failed to escape script tag")
		}
		expectedEscaped := "&lt;script&gt;alert(1)&lt;/script&gt;"
		if !strings.Contains(html, expectedEscaped) {
			t.Errorf("HTML report did not contain expected escaped form %q", expectedEscaped)
		}
	})

	t.Run("no raw secret appears in reports", func(t *testing.T) {
		rawSecretVal := "REAL_SECRET_XYZ"
		safeFindings := []EnrichedFinding{
			{
				RuleID:       "rule-secret",
				File:         "app.go",
				RiskScore:    80,
				RiskLevel:    "high",
				MaskedSecret: "REAL_****XYZ",
				CodeContext:  []string{"SECRET=" + rawSecretVal},
				Triage:       &Triage{Verdict: "real_secret", Source: "llm", Reason: "Secret found"},
			},
		}

		md := GenerateReport(safeFindings, "markdown")
		html := GenerateReport(safeFindings, "html")

		if strings.Contains(md, rawSecretVal) || strings.Contains(html, rawSecretVal) {
			t.Errorf("security violation: raw secret appeared in report output")
		}
	})

	t.Run("finding with nil triage renders correctly", func(t *testing.T) {
		md := GenerateReport(findings, "markdown")
		html := GenerateReport(findings, "html")

		if !strings.Contains(md, "rule-med") || !strings.Contains(html, "rule-med") {
			t.Errorf("finding with nil triage was not rendered in reports")
		}
	})
}
