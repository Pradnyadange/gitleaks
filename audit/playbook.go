package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ProviderType string

const (
	ProviderGitHub     ProviderType = "github"
	ProviderAWS        ProviderType = "aws"
	ProviderStripe     ProviderType = "stripe"
	ProviderPrivateKey ProviderType = "private-key"
	ProviderGeneric    ProviderType = "generic"
)

type RotationPlaybook struct {
	Provider       ProviderType
	Name           string
	Creation       string
	Deployment     string
	Revocation     string
	ImmediateRevok string
	AuditNotice    string
	ConsoleDomain  string
}

var ProviderPlaybooks = map[ProviderType]RotationPlaybook{
	ProviderGitHub: {
		Provider:       ProviderGitHub,
		Name:           "GitHub",
		Creation:       "Log in to github.com -> Settings -> Developer settings -> Personal access tokens. Click 'Generate new token', select the minimal required scopes, set an expiration, and copy the new token.",
		Deployment:     "Deploy the new token to your production environment variables, GitHub Actions Secrets, or key vault, and verify that services authenticate successfully.",
		Revocation:     "In GitHub Settings -> Developer settings -> Personal access tokens, find the exposed token and click 'Delete' / 'Revoke'.",
		ImmediateRevok: "If the credential may already be abused, revoke it immediately and accept the downtime.",
		AuditNotice:    "Inspect the GitHub Security Log (Account/Org Settings -> Security log) for unauthorized clones, workflow modifications, or permission changes during the exposure window.",
		ConsoleDomain:  "github.com",
	},
	ProviderAWS: {
		Provider:       ProviderAWS,
		Name:           "Amazon Web Services (AWS)",
		Creation:       "Open aws.amazon.com -> IAM Console -> Users -> Security credentials. Click 'Create access key' (or generate temporary credentials via AWS STS / IAM Roles).",
		Deployment:     "Update your applications, secret stores (AWS Secrets Manager / Parameter Store), and CI/CD pipelines with the new credentials and confirm functionality.",
		Revocation:     "In the IAM Console under Security credentials -> Access keys, change the exposed Access Key ID status to 'Inactive', confirm no errors occur, and then permanently delete it.",
		ImmediateRevok: "If the credential may already be abused, revoke it immediately and accept the downtime.",
		AuditNotice:    "Inspect AWS CloudTrail Event history for anomalous API calls made using the exposed access key ID during the exposure window.",
		ConsoleDomain:  "aws.amazon.com",
	},
	ProviderStripe: {
		Provider:       ProviderStripe,
		Name:           "Stripe",
		Creation:       "Log in to stripe.com -> Developers -> API keys. Click 'Create restricted key' or select the existing key and choose 'Roll key' with an expiration window (e.g. 12 hours) to avoid downtime.",
		Deployment:     "Deploy the new API key to your billing/payment microservices and verify webhook deliveries and payment requests succeed.",
		Revocation:     "In the Stripe Dashboard -> Developers -> API keys, revoke the old compromised API key once all services are operating on the replacement key.",
		ImmediateRevok: "If the credential may already be abused, revoke it immediately and accept the downtime.",
		AuditNotice:    "Review Stripe Dashboard -> Developers -> Logs for unexpected charge requests, customer data exports, or webhook destination edits.",
		ConsoleDomain:  "stripe.com",
	},
	ProviderPrivateKey: {
		Provider:       ProviderPrivateKey,
		Name:           "SSH / TLS Private Key",
		Creation:       "Generate a new cryptographic keypair using `ssh-keygen -t ed25519 -a 100 -C \"rotated key\"` (or generate a new TLS private key and certificate signing request).",
		Deployment:     "Distribute the new public key to target servers (~/.ssh/authorized_keys), Git deploy keys, or cloud metadata. Ensure connection tests succeed.",
		Revocation:     "Remove the old compromised public key from all servers (~/.ssh/authorized_keys), bastion hosts, and Git repository deploy settings.",
		ImmediateRevok: "If the credential may already be abused, revoke it immediately and accept the downtime.",
		AuditNotice:    "Inspect server authentication logs (/var/log/auth.log or /var/log/secure) for unauthorized SSH sessions during the exposure window.",
		ConsoleDomain:  "",
	},
	ProviderGeneric: {
		Provider:       ProviderGeneric,
		Name:           "Generic Credential / Token",
		Creation:       "Log in to the administrative portal of the issuing service and generate a new access token or secret with minimal necessary privileges.",
		Deployment:     "Update your production environment variables and secret management stores, and verify that dependent applications operate normally.",
		Revocation:     "Immediately revoke, disable, or delete the exposed secret from the service's admin console.",
		ImmediateRevok: "If the credential may already be abused, revoke it immediately and accept the downtime.",
		AuditNotice:    "Examine service access logs, authentication events, and API metrics for abnormal activities or suspicious IP addresses.",
		ConsoleDomain:  "",
	},
}

// DetectProvider maps a ruleID to a ProviderType
func DetectProvider(ruleID string) ProviderType {
	lower := strings.ToLower(ruleID)
	switch {
	case strings.HasPrefix(lower, "github-") || strings.Contains(lower, "github"):
		return ProviderGitHub
	case strings.HasPrefix(lower, "aws-") || strings.Contains(lower, "aws"):
		return ProviderAWS
	case strings.HasPrefix(lower, "stripe-") || strings.Contains(lower, "stripe"):
		return ProviderStripe
	case strings.HasPrefix(lower, "private-key") || strings.Contains(lower, "private-key") || strings.Contains(lower, "openssh") || strings.Contains(lower, "rsa"):
		return ProviderPrivateKey
	default:
		return ProviderGeneric
	}
}

// EscapeMarkdown safely escapes characters that can break markdown formatting (backticks, pipes, newlines, angle brackets, leading #)
func EscapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "#") {
		s = "\\" + s
		break
	}
	// Also escape any hashes in s
	s = strings.ReplaceAll(s, "#", "\\#")
	return s
}

// PlaybookOptions configures playbook and PR description generation
type PlaybookOptions struct {
	FixSummary *FixSummary
}

// GeneratePlaybook creates a credential rotation markdown document for real secrets and needs_review
func GeneratePlaybook(findings []EnrichedFinding, opts ...PlaybookOptions) string {
	var fixSum *FixSummary
	if len(opts) > 0 {
		fixSum = opts[0].FixSummary
	}

	// Filter out false positives and count ignored
	var active []EnrichedFinding
	ignoredCount := 0
	for _, f := range findings {
		verdict := ""
		if f.Triage != nil {
			verdict = f.Triage.Verdict
		}
		if verdict == "likely_false_positive" {
			ignoredCount++
			continue
		}
		active = append(active, f)
	}

	var b strings.Builder
	b.WriteString("# Incident Response: Credential Rotation Playbook\n\n")

	if len(active) == 0 {
		b.WriteString("No active credential leaks requiring rotation were identified.\n\n")
		if ignoredCount > 0 {
			b.WriteString(fmt.Sprintf("Ignored: %d\n", ignoredCount))
		}
		return b.String()
	}

	b.WriteString("> [!WARNING]\n")
	b.WriteString("> Hardcoded credentials in source code or Git history must be assumed compromised.\n")
	b.WriteString("> Removing credentials from source files does not invalidate active access keys. Follow the step-by-step procedures below immediately.\n\n")

	hasHistoryOnly := false
	for _, f := range active {
		if f.InHistoryOnly {
			hasHistoryOnly = true
			break
		}
	}

	if hasHistoryOnly {
		b.WriteString("> [!IMPORTANT]\n")
		b.WriteString("> One or more secrets were detected in Git history only. Even though they may no longer exist in the active working tree, they remain visible to anyone with clone access and must be revoked immediately.\n\n")
	}

	// 1. Executive Summary Table
	providerFindings := make(map[ProviderType][]EnrichedFinding)
	for _, f := range active {
		prov := DetectProvider(f.RuleID)
		providerFindings[prov] = append(providerFindings[prov], f)
	}

	var providers []ProviderType
	for p := range providerFindings {
		providers = append(providers, p)
	}
	sort.Slice(providers, func(i, j int) bool {
		return string(providers[i]) < string(providers[j])
	})

	b.WriteString("## Executive Summary\n\n")
	b.WriteString("| Provider | Exposed Count | Highest Risk Level |\n")
	b.WriteString("| :--- | :--- | :--- |\n")

	riskPriority := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	for _, p := range providers {
		pb := ProviderPlaybooks[p]
		items := providerFindings[p]
		highestRisk := "info"
		highestVal := 0
		for _, item := range items {
			val := riskPriority[strings.ToLower(item.RiskLevel)]
			if val > highestVal {
				highestVal = val
				highestRisk = item.RiskLevel
			}
		}
		if highestRisk == "" {
			highestRisk = "medium"
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %s |\n",
			EscapeMarkdown(pb.Name),
			len(items),
			EscapeMarkdown(strings.ToUpper(highestRisk)),
		))
	}
	b.WriteString("\n")

	if ignoredCount > 0 {
		b.WriteString(fmt.Sprintf("Ignored: %d\n\n", ignoredCount))
	}

	// 2. Exposed Credentials Inventory Table
	b.WriteString("## Exposed Credentials Inventory\n\n")
	b.WriteString("| Rule ID | File | Line | Masked Secret | Status |\n")
	b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")

	// Map findings to fix status
	type fixInfo struct {
		applied bool
		branch  string
		reason  string
	}
	findingStatusMap := make(map[string]fixInfo)
	if fixSum != nil {
		for _, st := range fixSum.Statuses {
			key := fmt.Sprintf("%s:%s:%d", st.Finding.RuleID, st.Finding.File, st.Finding.StartLine)
			findingStatusMap[key] = fixInfo{
				applied: fixSum.AppliedCount > 0 && st.Eligible,
				branch:  fixSum.Branch,
				reason:  st.Reason,
			}
		}
	}

	for _, f := range active {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.File, f.StartLine)
		statusText := "Not fixed in this run"
		if f.InHistoryOnly {
			statusText = "History only: rotate the key"
		} else if info, ok := findingStatusMap[key]; ok {
			if info.applied {
				branchName := info.branch
				if branchName == "" {
					branchName = "remediation branch"
				}
				statusText = fmt.Sprintf("Fixed on branch %s", branchName)
			} else if info.reason != "" {
				statusText = "Manual fix needed"
			}
		}

		b.WriteString(fmt.Sprintf("| %s | `%s` | %d | `%s` | %s |\n",
			EscapeMarkdown(f.RuleID),
			EscapeMarkdown(f.File),
			f.StartLine,
			EscapeMarkdown(f.MaskedSecret),
			EscapeMarkdown(statusText),
		))
	}
	b.WriteString("\n")

	// 3. Provider Rotation Procedures
	for _, p := range providers {
		pb := ProviderPlaybooks[p]
		items := providerFindings[p]

		b.WriteString(fmt.Sprintf("## %s Rotation Procedure\n\n", pb.Name))
		b.WriteString("Verify these steps against the provider's current documentation.\n\n")
		b.WriteString(fmt.Sprintf("Affected Findings: %d\n\n", len(items)))
		b.WriteString(fmt.Sprintf("### Step 1: Create New Credential\n%s\n\n", pb.Creation))
		b.WriteString(fmt.Sprintf("### Step 2: Deploy New Credential\n%s\n\n", pb.Deployment))
		b.WriteString(fmt.Sprintf("### Step 3: Revoke Compromised Credential\n%s\n\n", pb.Revocation))
		b.WriteString(fmt.Sprintf("> [!NOTE]\n> %s\n\n", pb.ImmediateRevok))
		b.WriteString(fmt.Sprintf("### Step 4: Audit & Verify\n%s\n\n", pb.AuditNotice))
		if pb.ConsoleDomain != "" {
			b.WriteString(fmt.Sprintf("Management Console: `%s`\n\n", pb.ConsoleDomain))
		}
	}

	// 4. Git History Section
	b.WriteString("## Git History & Remediation\n\n")
	b.WriteString("Credential removal from source code does not remove it from Git commit history. Anyone with clone or pull access can read previous commits. ")
	b.WriteString("Rotating and invalidating the credential at the provider is the primary and essential fix. ")
	b.WriteString("Do not attempt destructive Git history rewriting (such as `git filter-repo` or `git filter-branch`) without coordination, as forced pushes break shared branches.\n")

	return b.String()
}

// GeneratePRDescription creates a pull request description summarizing auto-fix changes and providing a checklist
func GeneratePRDescription(findings []EnrichedFinding, opts ...PlaybookOptions) string {
	var fixSum *FixSummary
	if len(opts) > 0 {
		fixSum = opts[0].FixSummary
	}

	var b strings.Builder
	b.WriteString("## SecretSentinel Remediation PR\n\n")

	// Only findings actually remediated by fix engine appear in the remediation table
	type remediatedFinding struct {
		file   string
		ruleID string
		envVar string
	}
	var remediated []remediatedFinding
	var envVarList []string
	envVarSeen := make(map[string]bool)

	if fixSum != nil && fixSum.AppliedCount > 0 {
		for _, st := range fixSum.Statuses {
			if st.Eligible && !st.Finding.InHistoryOnly {
				envVar := st.EnvVar
				if envVar == "" {
					envVar = DeriveSmartEnvVarName(st.OldLine, st.Finding.RawSecret, st.Finding.RuleID, DetectLanguage(st.File), make(map[string]bool))
				}
				remediated = append(remediated, remediatedFinding{
					file:   st.File,
					ruleID: st.Finding.RuleID,
					envVar: envVar,
				})
				if !envVarSeen[envVar] {
					envVarSeen[envVar] = true
					envVarList = append(envVarList, envVar)
				}
			}
		}
	}

	if len(remediated) == 0 {
		b.WriteString("No credentials were automatically remediated in this run.\n\n")
		b.WriteString("Status: Not fixed in this run (run with `--apply-fix` to apply remediation).\n")
		return b.String()
	}

	b.WriteString("### Summary of Remediations\n\n")
	b.WriteString("This pull request replaces hardcoded credentials with environment variable lookups and ensures sensitive configuration files are untracked.\n\n")
	b.WriteString("> [!NOTE]\n")
	b.WriteString("> The Git diff shows old exposed credential values on removed lines. These credentials must be rotated.\n\n")

	b.WriteString("| File | Rule ID | Environment Variable |\n")
	b.WriteString("| :--- | :--- | :--- |\n")

	for _, rem := range remediated {
		b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` |\n",
			EscapeMarkdown(rem.file),
			EscapeMarkdown(rem.ruleID),
			EscapeMarkdown(rem.envVar),
		))
	}
	b.WriteString("\n")

	b.WriteString("### Required Environment Variables\n\n")
	b.WriteString("Ensure the following environment variables are configured in production and CI/CD secret stores:\n\n")
	sort.Strings(envVarList)
	for _, v := range envVarList {
		b.WriteString(fmt.Sprintf("- `%s`\n", EscapeMarkdown(v)))
	}
	b.WriteString("\n")

	b.WriteString("### What This Does Not Do\n\n")
	b.WriteString("- Git history is not rewritten (historical commits still contain earlier values; credentials must be revoked).\n")
	b.WriteString("- Changes are committed to a remediation branch and are not automatically pushed or merged to protected branches.\n")
	b.WriteString("- Provider credentials are not automatically rotated; follow the rotation playbook to invalidate them.\n\n")

	b.WriteString("### Post-Merge Checklist\n\n")
	b.WriteString("- [ ] Revoke and rotate all exposed credentials using the rotation playbook\n")
	b.WriteString("- [ ] Verify environment variables are populated in deployment environments\n")
	b.WriteString("- [ ] Ensure no local `.env` files are tracked in version control\n")
	b.WriteString("- [ ] Review audit logs for unauthorized access during the credential exposure window\n")

	return b.String()
}

// WritePlaybookFile writes the rotation playbook to the specified path
func WritePlaybookFile(findings []EnrichedFinding, path string, opts ...PlaybookOptions) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	content := GeneratePlaybook(findings, opts...)
	return os.WriteFile(path, []byte(content), 0644)
}

// WritePRDescriptionFile writes the PR description markdown to the specified path
func WritePRDescriptionFile(findings []EnrichedFinding, path string, opts ...PlaybookOptions) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	content := GeneratePRDescription(findings, opts...)
	return os.WriteFile(path, []byte(content), 0644)
}
