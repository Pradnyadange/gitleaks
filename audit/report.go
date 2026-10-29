package audit

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
)

func SortFindingsByScore(findings []EnrichedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})
}

func sanitizeContextLine(line string, maskedSecret string) string {
	if strings.Contains(maskedSecret, "****") {
		parts := strings.SplitN(maskedSecret, "****", 2)
		prefix, suffix := parts[0], parts[1]
		if prefix != "" && suffix != "" {
			var sb strings.Builder
			remaining := line
			for {
				pIdx := strings.Index(remaining, prefix)
				if pIdx == -1 {
					sb.WriteString(remaining)
					break
				}
				sb.WriteString(remaining[:pIdx])
				rest := remaining[pIdx+len(prefix):]
				sIdx := strings.Index(rest, suffix)
				if sIdx == -1 {
					sb.WriteString(remaining[pIdx:])
					break
				}
				sb.WriteString(maskedSecret)
				remaining = rest[sIdx+len(suffix):]
			}
			return sb.String()
		}
	}
	return line
}

func sanitizeCodeContext(codeContext []string, maskedSecret string) []string {
	if len(codeContext) == 0 {
		return nil
	}
	out := make([]string, len(codeContext))
	for i, line := range codeContext {
		out[i] = sanitizeContextLine(line, maskedSecret)
	}
	return out
}

func GenerateReport(findings []EnrichedFinding, format string) string {
	SortFindingsByScore(findings)
	if format == "html" {
		return generateHTMLReport(findings)
	}
	return generateMarkdownReport(findings)
}

func generateMarkdownReport(findings []EnrichedFinding) string {
	var sb strings.Builder
	sb.WriteString("# SecretSentinel Audit Report\n\n")

	// Summary
	criticalCount, highCount, mediumCount, lowCount, infoCount := 0, 0, 0, 0, 0
	realCount, fpCount, reviewCount, naCount := 0, 0, 0, 0
	for _, f := range findings {
		switch f.RiskLevel {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		case "info":
			infoCount++
		}
		if f.Triage != nil {
			switch f.Triage.Verdict {
			case "real_secret":
				realCount++
			case "likely_false_positive":
				fpCount++
			case "needs_review":
				reviewCount++
			default:
				naCount++
			}
		} else {
			naCount++
		}
	}

	sb.WriteString("## Summary\n")
	sb.WriteString(fmt.Sprintf("- **Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", len(findings)))
	sb.WriteString(fmt.Sprintf("- **Risk Levels:** Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n", criticalCount, highCount, mediumCount, lowCount, infoCount))
	sb.WriteString(fmt.Sprintf("- **Verdicts:** Real Secret: %d, False Positive: %d, Needs Review: %d, N/A: %d\n\n", realCount, fpCount, reviewCount, naCount))

	// Ranked Table
	sb.WriteString("## Ranked Findings\n")
	sb.WriteString("| Rule ID | File | Risk Level | Score | Verdict | Source |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")

	var falsePositives []EnrichedFinding
	for _, f := range findings {
		if f.Triage != nil && f.Triage.Verdict == "likely_false_positive" {
			falsePositives = append(falsePositives, f)
		}
		verdict := "N/A"
		source := "N/A"
		if f.Triage != nil {
			verdict = f.Triage.Verdict
			source = f.Triage.Source
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s | %s |\n",
			f.RuleID, f.File, f.RiskLevel, f.RiskScore, verdict, source))
	}

	// Detail Blocks for Non-Info Findings
	sb.WriteString("\n## Detailed Findings\n")
	for _, f := range findings {
		if f.RiskLevel == "info" {
			continue
		}
		sb.WriteString(fmt.Sprintf("### Rule: %s (`%s:%d`)\n", f.RuleID, f.File, f.StartLine))
		sb.WriteString(fmt.Sprintf("- **Masked Secret:** `%s`\n", f.MaskedSecret))
		if f.Triage != nil {
			sb.WriteString(fmt.Sprintf("- **Verdict & Reason:** %s — *%s*\n", f.Triage.Verdict, f.Triage.Reason))
		} else {
			sb.WriteString("- **Verdict & Reason:** N/A\n")
		}
		sb.WriteString(fmt.Sprintf("- **Level & Factors:** %s | Factors: %s\n", f.RiskLevel, strings.Join(f.RiskFactors, ", ")))
		sb.WriteString(fmt.Sprintf("- **Impact:** %s\n", f.RiskImpact))
		if f.InHistoryOnly {
			sb.WriteString("- ⚠️ **Warning:** Present in git history only (deleted from working tree).\n")
		} else {
			sb.WriteString("- **History:** Present in active working tree.\n")
		}
		sanitizedCtx := sanitizeCodeContext(f.CodeContext, f.MaskedSecret)
		if len(sanitizedCtx) > 0 {
			sb.WriteString("- **Code Context:**\n")
			for _, ctxLine := range sanitizedCtx {
				sb.WriteString(fmt.Sprintf("  > `%s`\n", ctxLine))
			}
		}
		sb.WriteString("- **Recommended action:** rotate the credential, then remove it from code.\n\n")
	}

	// Likely False Positives
	if len(falsePositives) > 0 {
		sb.WriteString("## Likely False Positives\n")
		for _, fp := range falsePositives {
			reason := "N/A"
			if fp.Triage != nil {
				reason = fp.Triage.Reason
			}
			sb.WriteString(fmt.Sprintf("- `%s` in `%s` — %s\n", fp.RuleID, fp.File, reason))
		}
	}

	return sb.String()
}

func generateHTMLReport(findings []EnrichedFinding) string {
	cleanFindings := make([]EnrichedFinding, len(findings))
	copy(cleanFindings, findings)
	for i := range cleanFindings {
		cleanFindings[i].CodeContext = sanitizeCodeContext(cleanFindings[i].CodeContext, cleanFindings[i].MaskedSecret)
	}

	tmplStr := `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SecretSentinel Audit Report</title>
<style>
body { font-family: sans-serif; margin: 20px; color: #333; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f4f4f4; }
.critical { color: #d9534f; font-weight: bold; }
.high { color: #f0ad4e; font-weight: bold; }
.medium { color: #f0ad4e; }
.low { color: #5bc0de; }
.info { color: #5cb85c; }
.card { border: 1px solid #ccc; padding: 15px; margin-bottom: 15px; border-radius: 5px; background: #fafafa; }
pre { background: #eee; padding: 5px; }
</style>
</head>
<body>
<h1>SecretSentinel Audit Report</h1>
<h2>Summary</h2>
<ul>
  <li><strong>Total Findings:</strong> {{len .Findings}}</li>
</ul>

<h2>Ranked Findings</h2>
<table>
<tr><th>Rule ID</th><th>File</th><th>Risk Level</th><th>Score</th><th>Verdict</th><th>Source</th></tr>
{{range .Findings}}
<tr><td>{{.RuleID}}</td><td>{{.File}}</td><td><span class="{{.RiskLevel}}">{{.RiskLevel}}</span></td><td>{{.RiskScore}}</td><td>{{if .Triage}}{{.Triage.Verdict}}{{else}}N/A{{end}}</td><td>{{if .Triage}}{{.Triage.Source}}{{else}}N/A{{end}}</td></tr>
{{end}}
</table>

<h2>Detailed Findings</h2>
{{range .Findings}}
{{if ne .RiskLevel "info"}}
<div class="card">
  <h3>{{.RuleID}} ({{.File}}:{{.StartLine}} )</h3>
  <p><strong>Risk Level:</strong> {{.RiskLevel}} (Score: {{.RiskScore}})</p>
  <p><strong>Masked Secret:</strong> <code>{{.MaskedSecret}}</code></p>
  {{if .Triage}}<p><strong>Verdict & Reason:</strong> {{.Triage.Verdict}} — <em>{{.Triage.Reason}}</em></p>{{end}}
  <p><strong>Level & Factors:</strong> {{.RiskLevel}} | Factors: {{range .RiskFactors}}{{.}}; {{end}}</p>
  <p><strong>Impact:</strong> {{.RiskImpact}}</p>
  {{if .InHistoryOnly}}<p>⚠️ <strong>Warning:</strong> Present in git history only.</p>{{end}}
  {{if .CodeContext}}<p><strong>Code Context:</strong></p>
  <pre>{{range .CodeContext}}{{.}}
{{end}}</pre>
  {{end}}
  <p><strong>Recommended action:</strong> rotate the credential, then remove it from code.</p>
</div>
{{end}}
{{end}}
</body>
</html>`

	t := template.Must(template.New("report").Parse(tmplStr))
	var sb strings.Builder
	data := struct {
		Findings []EnrichedFinding
	}{Findings: cleanFindings}
	_ = t.Execute(&sb, data)
	return sb.String()
}
