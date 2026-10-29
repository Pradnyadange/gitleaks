package audit

import (
	"fmt"
	"strings"
)

/*
Risk Scoring Weights Table:
| Factor / Attribute      | Weight / Points Adjustment |
|-------------------------|----------------------------|
| Base Score              | +10                        |
| Path Type: test/example | -5                         |
| Path Type: config       | +15                        |
| Path Type: source       | +20                        |
| Active in Git History   | +15                        |
| History Only            | -10                        |
| High Entropy (>4.0)     | +10                        |
| Triage: False Positive  | -30                        |
| Triage: Real Secret     | +25                        |
| Triage: Needs Review    | +5                         |
| LLM Confidence Scaling  | + (Confidence * 10)        |
*/

type RiskLevel string

const (
	RiskInfo     = "info"
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

var impactTemplates = map[string]string{
	"cloud":          "Exposure of cloud provider credentials may allow unauthorized resource provisioning and data exfiltration.",
	"payment":        "Compromise of payment gateway tokens enables fraudulent financial transactions and breach of compliance.",
	"source-control": "Leaked version control or CI/CD tokens grant unauthorized repository access and pipeline tampering capabilities.",
	"private key":    "Exposed private cryptographic keys allow identity spoofing, decryption of secure traffic, and system compromise.",
	"generic":        "Exposure of sensitive credentials increases attack surface and risk of unauthorized system access.",
}

func getImpactText(ruleID string) string {
	lower := strings.ToLower(ruleID)
	if strings.Contains(lower, "aws") || strings.Contains(lower, "azure") || strings.Contains(lower, "gcp") || strings.Contains(lower, "cloud") {
		return impactTemplates["cloud"]
	}
	if strings.Contains(lower, "stripe") || strings.Contains(lower, "paypal") || strings.Contains(lower, "payment") {
		return impactTemplates["payment"]
	}
	if strings.Contains(lower, "github") || strings.Contains(lower, "gitlab") || strings.Contains(lower, "npm") || strings.Contains(lower, "token") {
		return impactTemplates["source-control"]
	}
	if strings.Contains(lower, "rsa") || strings.Contains(lower, "ssh") || strings.Contains(lower, "private") || strings.Contains(lower, "key") {
		return impactTemplates["private key"]
	}
	return impactTemplates["generic"]
}

func CalculateRisk(f EnrichedFinding) (int, string, []string, string) {
	score := 10
	var factors []string

	if f.PathType == "test" || f.PathType == "example" || f.PathType == "docs" {
		factors = append(factors, "Path type is non-production ("+f.PathType+")")
		score -= 5
	} else if f.PathType == "config" {
		factors = append(factors, "Path type is configuration")
		score += 15
	} else {
		factors = append(factors, "Path type is source code")
		score += 20
	}

	if f.InHistoryOnly {
		factors = append(factors, "Present in git history only (deleted)")
		score -= 10
	} else {
		factors = append(factors, "Present in active working tree")
		score += 15
	}

	if f.Entropy > 4.0 {
		factors = append(factors, "High entropy value (>4.0)")
		score += 10
	}

	if f.Triage != nil {
		switch f.Triage.Verdict {
		case "likely_false_positive":
			factors = append(factors, "Triaged as likely false positive")
			score -= 30
		case "real_secret":
			factors = append(factors, "Triaged as real secret")
			score += 25
		case "needs_review":
			factors = append(factors, "Triaged as needs review")
			score += 5
		}
		if f.Triage.Source == "llm" {
			confBonus := int(f.Triage.Confidence * 10)
			score += confBonus
			factors = append(factors, fmt.Sprintf("LLM confidence bonus (+%d)", confBonus))
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	var level string
	if f.Triage != nil && f.Triage.Source == "llm" && f.Triage.Verdict == "likely_false_positive" {
		level = RiskInfo
	} else {
		switch {
		case score >= 75:
			level = RiskCritical
		case score >= 50:
			level = RiskHigh
		case score >= 25:
			level = RiskMedium
		default:
			level = RiskLow
		}
	}

	impact := getImpactText(f.RuleID)
	return score, level, factors, impact
}
