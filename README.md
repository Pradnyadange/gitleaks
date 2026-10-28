SecretSentinel
An AI-powered code security auditor built on top of Gitleaks.

Gitleaks finds possible secrets. SecretSentinel answers the questions developers actually need answered: Is it real? How dangerous is it? How do I fix it? How do I recover?

Status
Phase	Goal	Status
1. Foundation	gitleaks audit command with enriched findings	Done
2. AI triage	Verdict, confidence and reason per finding (Gemini + offline fallback + robust caching + dry-run)	Done
3. Risk and allowlist	Risk ranking, auto-generated .gitleaksignore, Markdown/HTML report	Planned
4. Auto-fix and recovery	Fix pull request, key rotation playbooks	Planned
5. Demo and submission	Demo repo, tests, final presentation	Planned
The Problem
Developers accidentally commit API keys, tokens and passwords, and the secret stays in git history even after the file is deleted.

Automated bots scan public repositories and can find exposed credentials within minutes.

One exposed key can open servers, databases and cloud accounts, putting user data at risk.

Small teams have no security engineer, no time to review every commit, and suffer alert fatigue from noisy scanners.

What SecretSentinel Adds
Gap in Gitleaks alone	SecretSentinel feature	Phase
Output is a raw list of matches	Enriched findings: code context, masked secret, path type, history-only flag	1 (done)
Cannot tell a real key from a placeholder	AI triage with verdict, confidence, reason, caching, and robust fallback	2 (done)
All findings look equally urgent	Risk scoring and ranking	3
Allowlists are written by hand	Auto-generated allowlist from confirmed false positives	3
Detects but never fixes	Auto-fix pull request (env var, .env.example, .gitignore)	4
No recovery guidance	Provider-specific rotation playbook	4
How It Works
Repo or folder
   -> Gitleaks scan (unchanged engine)
   -> Enrichment: masked secret, code context, path type, history-only flag
   -> Triage: Gemini verdict (or offline heuristics), model & prompt-version cached
   -> audit-findings.json
Quick Start
Requires Go.

Bash
git clone https://github.com/Pradnyadange/gitleaks.git
cd gitleaks
go build -o gitleaks .
1. Enrich findings only (no AI, no network):

Bash
./gitleaks audit --mode dir ./path/to/project --audit-output audit-findings.json
./gitleaks audit --mode git ./path/to/repo    --audit-output audit-findings.json
2. Add triage without any network (heuristics only):

Bash
./gitleaks audit --mode git ./path/to/repo --triage --offline
3. Preview prompts without sending anything (Dry Run):

Bash
./gitleaks audit --mode git ./path/to/repo --triage --triage-dry-run
4. Add AI triage with Gemini:

Bash
export GEMINI_API_KEY="your-key"     # PowerShell: $env:GEMINI_API_KEY = "your-key"
export GEMINI_MODEL="gemini-2.5-flash"  # or pass --gemini-model
./gitleaks audit --mode git ./path/to/repo --triage
Flags
Flag	Default	Description
--mode	git	git scans commit history, dir scans files on disk
--audit-output	audit-findings.json	Output JSON file
--context-lines	20	Code context lines before and after each finding
--include-raw-secret	false	Write raw secrets to the output. Leave off
--triage	false	Enable triage of each finding
--offline	false	Triage with heuristics only, zero network calls
--triage-dry-run	false	Print the exact prompts that would be sent, send nothing (bypasses API key checks)
--gemini-model	env GEMINI_MODEL	Gemini model name. No default is hard-coded
--triage-concurrency	3	Parallel triage workers
--max-findings	50	Maximum findings to triage per run
--triage-context-lines	10	Context lines included in the prompt
Output & Triage Summary
After a triage run, an informative summary is printed:

Plaintext
=== SECRET SENTINEL TRIAGE SUMMARY ===
Total Findings Processed: 7
Verdicts:  real_secret: 3, likely_false_positive: 4
Sources:    llm: 7
API Calls Made: 3
Cache Hits: 4
LLM Successes: 3
LLM Failures: 0
======================================
Triage verdicts
Verdict	Meaning
real_secret	Looks like a genuine credential in production-relevant code
likely_false_positive	Placeholder, test fixture, documentation example, hash, ID, or non-secret
needs_review	Not enough evidence; conservative fallback
Caching
LLM-only caching: Only results derived successfully from the LLM are cached in .secretsentinel-cache.json. Heuristic results and failed LLM calls are never cached.

Cache key structure: Combines fingerprint + model name + PromptVersion, ensuring changes to the model or system prompt automatically invalidate old entries.

Privacy and Security Design
Zero raw secrets in prompts: Prompts contain only masked values, lengths, and redacted context. Unit tests verify raw secrets never leak into prompts.

Strict masking threshold: Partial masking (first 4 + **** + last 2) applies only when len(secret) >= 16. Shorter secrets are fully masked with asterisks.

Prompt-injection defense: Code context is treated as untrusted data, system prompts instruct the model to ignore embedded instructions, and all outputs are validated.

Secure key handling: API keys are read solely from the environment (x-goog-api-key header) and are never logged or exposed in dry-run mode.

Testing
Run the test suite across all packages:

Bash
go build ./...
go test -v ./audit/...
Covered in tests:

Secret masking boundaries (15, 16, and 17 characters)

Path classification and context extraction edge cases

Mock LLM triage integration and safety checks

Malformed JSON handling, invalid verdicts, and confidence clamping (1.7 
→ 1.0)

Cache isolation, offline non-caching, model invalidation, and failure fallbacks

Dry-run validation bypass with empty keys

Project Structure
cmd/
  audit.go            # CLI command, flags, validation, and triage summary
audit/
  types.go            # EnrichedFinding and Triage structs
  mask.go             # Secret masking (16-character boundary rule)
  pathtype.go         # Path classification
  context.go          # Code context extraction and redaction
  llm.go              # LLMClient interface
  gemini.go           # Gemini REST client (net/http, retries, backoff)
  prompt.go           # System prompt and user prompt builder
  heuristics.go       # Offline heuristic fallback
  triage.go           # Worker pool, caching logic, and response validation
  audit_test.go       # Core unit tests
  cache_test.go       # Isolated cache and failure tests
Credits and License
SecretSentinel is a fork of gitleaks/gitleaks by Zachary Rice and contributors, released under the MIT License. See LICENSE.
