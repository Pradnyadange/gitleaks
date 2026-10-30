# SecretSentinel

**An AI-powered code security auditor built on top of [Gitleaks](https://github.com/gitleaks/gitleaks).**



> Gitleaks finds *possible* secrets. SecretSentinel answers the questions developers actually need answered: **Is it real? How dangerous is it? How do I fix it? How do I recover?**

---

## Status

| Phase | Goal | Status |
|---|---|---|
| 1. Foundation | `gitleaks audit` command with enriched findings | **Done** |
| 2. AI triage | Verdict, confidence and reason per finding (Gemini + offline fallback + cache) | **Done** |
| 3. Risk and allowlist | Risk ranking, auto-generated `.gitleaksignore`, Markdown/HTML report | **Done** |
| 4. Auto-fix and recovery | Fix pull request, key rotation playbooks | Planned |
| 5. Demo and submission | Demo repo, tests, final presentation | Planned |

This README documents what exists **today (Phases 1 and 2)**. Anything marked Planned is not implemented yet.

---

## The Problem

- Developers accidentally commit API keys, tokens and passwords, and the secret stays in git history even after the file is deleted.
- Automated bots scan public repositories and can find exposed credentials within minutes.
- One exposed key can open servers, databases and cloud accounts, putting user data at risk.
- Small teams have no security engineer, no time to review every commit, and suffer alert fatigue from noisy scanners.

## What Gitleaks Already Does (not re-claimed here)

Gitleaks provides git-history, directory and stdin scanning, a regex and entropy rule engine, allowlists (`.gitleaksignore`, `gitleaks:allow`), baselines, JSON/SARIF/CSV/JUnit reports, redaction, and CI exit codes. SecretSentinel uses it unchanged as its detection engine.

## What SecretSentinel Adds

| Gap in Gitleaks alone | SecretSentinel feature | Phase |
|---|---|---|
| Output is a raw list of matches | Enriched findings: code context, masked secret, path type, history-only flag | 1 (done) |
| Cannot tell a real key from a placeholder | AI triage with verdict, confidence and reason | 2 (done) |
| All findings look equally urgent | Risk scoring and ranking | 3 |
| Allowlists are written by hand | Auto-generated allowlist from confirmed false positives | 3 |
| Detects but never fixes | Auto-fix pull request (env var, `.env.example`, `.gitignore`) | 4 |
| No recovery guidance | Provider-specific rotation playbook | 4 |

---

## How It Works (today)

```
Repo or folder
   -> Gitleaks scan (unchanged engine)
   -> Enrichment: masked secret, code context, path type, history-only flag
   -> Triage: Gemini verdict (or offline heuristics), cached by fingerprint
   -> audit-findings.json
```

## Quick Start

Requires [Go](https://go.dev/dl/).

```bash
git clone https://github.com/Pradnyadange/gitleaks.git
cd gitleaks
go build -o gitleaks .
```

**1. Enrich findings only (no AI, no network):**

```bash
./gitleaks audit --mode dir ./path/to/project --audit-output audit-findings.json
./gitleaks audit --mode git ./path/to/repo    --audit-output audit-findings.json
```

**2. Add triage without any network (heuristics only):**

```bash
./gitleaks audit --mode git ./path/to/repo --triage --offline
```

**3. Add AI triage with Gemini:**

```bash
export GEMINI_API_KEY="your-key"      # PowerShell: $env:GEMINI_API_KEY = "your-key"
export GEMINI_MODEL="gemini-2.5-flash"  # or pass --gemini-model
./gitleaks audit --mode git ./path/to/repo --triage
```

List the models your key can use, then pick a stable (non-preview) Flash model:

```powershell
Invoke-RestMethod -Uri "https://generativelanguage.googleapis.com/v1beta/models" `
  -Headers @{"x-goog-api-key" = $env:GEMINI_API_KEY} |
  Select-Object -ExpandProperty models |
  Where-Object { $_.supportedGenerationMethods -contains "generateContent" } |
  Select-Object name
```

On Windows without building: `go run main.go audit --mode git "D:\path\to\repo" --triage`.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `git` | `git` scans commit history, `dir` scans files on disk |
| `--audit-output` | `audit-findings.json` | Output JSON file |
| `--context-lines` | `20` | Code context lines before and after each finding |
| `--include-raw-secret` | `false` | Write raw secrets to the output. **Leave off** |
| `--triage` | `false` | Enable triage of each finding |
| `--offline` | `false` | Triage with heuristics only, zero network calls |
| `--triage-dry-run` | `false` | Print the prompts that would be sent, send nothing |
| `--gemini-model` | env `GEMINI_MODEL` | Gemini model name. No default is hard-coded |
| `--triage-concurrency` | `3` | Parallel triage workers |
| `--max-findings` | `50` | Maximum findings to triage per run |
| `--triage-context-lines` | `10` | Context lines included in the prompt (kept small on purpose) |

Existing Gitleaks flags (`--config`, `--baseline-path`, `--gitleaks-ignore-path`) still apply.

### Environment variables

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Gemini key, read only from the environment and sent in the `x-goog-api-key` header. Never a flag, never logged |
| `GEMINI_MODEL` | Model name used when `--gemini-model` is not set |

Running `--triage` without `--offline` and without a key or model exits with a clear error. It does not silently fall back to heuristics.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No leaks found |
| `1` | Leaks found, or an error occurred (same as upstream Gitleaks) |

---

## Output

Illustrative record (values shortened; field names match the real output):

```json
{
  "rule_id": "stripe-access-token",
  "description": "Stripe access token",
  "file": ".env",
  "start_line": 1,
  "end_line": 1,
  "commit": "9e77c95...",
  "author": "...",
  "date": "...",
  "entropy": 4.1,
  "fingerprint": "9e77c95...:.env:stripe-access-token:1",
  "path_type": "config",
  "in_history_only": false,
  "secret_length": 32,
  "masked_secret": "sk_l****Ho",
  "code_context": ["STRIPE_KEY=sk_l****Ho"],
  "triage": {
    "verdict": "real_secret",
    "confidence": 0.95,
    "reason": "Live-format Stripe key assigned in a config file.",
    "source": "llm",
    "cached": false
  }
}
```

After a triage run, a summary is printed:

```
=== SECRET SENTINEL TRIAGE SUMMARY ===
Total Findings Processed: 7
Verdicts:   real_secret: 3, likely_false_positive: 4
Sources:    llm: 7
API Calls Made: 3
Cache Hits: 4
LLM Successes: 3
LLM Failures: 0
```

### Triage verdicts

| Verdict | Meaning |
|---|---|
| `real_secret` | Looks like a genuine credential in production-relevant code |
| `likely_false_positive` | Placeholder, test fixture, documentation example, hash, ID, or non-secret |
| `needs_review` | Not enough evidence; the model is told to be conservative |

Each triage result includes a `confidence` (0 to 1, clamped), a one-sentence `reason`, a `source` (`llm` or `heuristic`), and a `cached` flag.

### Offline heuristics

Used by `--offline` and as the automatic fallback when an LLM call fails. They never output `real_secret`:

- test, example or docs paths -> `likely_false_positive`
- placeholder-style text in the secret or context (for example `example`, `changeme`, `dummy`, `placeholder`) -> `likely_false_positive`
- everything else -> `needs_review`

### Cache

Results are cached in `.secretsentinel-cache.json` so reruns cost nothing.

- Only results from the LLM are cached. Heuristic results are never cached or served as cache hits.
- The cache key combines the finding fingerprint, the model name and a prompt version, so changing the model or prompt invalidates old entries.
- Failed LLM calls fall back to heuristics, are not cached, and are counted as failures.

### Path types

| Path type | Matches |
|---|---|
| `test` | `/test/`, `test_`, `_test.go`, `specs/` |
| `example` | `example`, `sample`, `demo` |
| `docs` | `doc/`, `.md`, `.rst`, `.txt` |
| `vendor` | `vendor/`, `node_modules/`, `third_party/` |
| `config` | `config/`, `.env`, `.json`, `.yml`, `.yaml`, `.toml`, `.ini` |
| `source` | everything else |

---

## Privacy and Security Design

Sending code to an LLM is itself a risk, so SecretSentinel is built to send as little as possible:

- **Raw secrets never reach the prompt.** Prompts contain only the masked value, the secret's length, and redacted code context. A test fails if a prompt ever contains a raw secret.
- **Short secrets reveal nothing.** Partial masking (first 4 characters, `****`, last 2) applies only to secrets of 16 or more characters. Shorter secrets are fully masked.
- **Small context window.** Only 10 lines around the finding are sent by default (`--triage-context-lines`).
- **Free-tier note.** Google states that content sent through the free Gemini API tier may be used to improve its products, so the redaction above matters. Use a paid tier or the `--offline` mode for sensitive repositories.
- **Prompt-injection defense.** Code context is treated as untrusted data. The system prompt tells the model to ignore any instructions found inside it, and every response is validated (allowed verdict values, clamped confidence, truncated reason).
- **Key handling.** The API key is read only from the environment and is never logged. Rotate any key that has ever been pasted into a chat, file or commit.
- **Safe failure.** If the model returns bad output or the API fails, the finding falls back to heuristics and the scan continues.
- **Dry run.** `--triage-dry-run` prints exactly what would be sent so you can inspect it first.

Never commit audit output. Add `*-audit.json`, `audit-findings.json`, `.secretsentinel-cache.json` and `.env` to `.gitignore`.

---

## Results So Far

On a small demo repository with 7 findings (3 real leaks, 4 decoys such as a test file, a docs example, a test fixture and an `.env.example` placeholder), AI triage classified all 7 as expected: 3 `real_secret` and 4 `likely_false_positive`, with 0 failures. A second run made 0 API calls.

This is a small, hand-built set and several decoys carry obvious hints in their path or comments, so treat it as a working demonstration and not as an accuracy benchmark. Harder cases (a real key in a test or docs file, a revoked key in source) are the next evaluation step.

---

## Project Structure (SecretSentinel additions)

```
cmd/
  audit.go            # `audit` command, flags, JSON output, triage summary
audit/
  types.go            # EnrichedFinding and Triage structs
  mask.go             # secret masking (16-character boundary)
  pathtype.go         # path classification
  context.go          # code context extraction and redaction
  llm.go              # LLMClient interface
  gemini.go           # Gemini REST client (net/http, retries with backoff)
  prompt.go           # system prompt and user prompt builder
  heuristics.go       # offline fallback triage
  triage.go           # worker pool, cache, response validation
  audit_test.go       # unit tests
```

The Gitleaks detection engine (`detect/`, `sources/`, `config/`) is **not modified**. SecretSentinel layers on top of it, which keeps upstream behavior intact.

## Testing

```bash
go build ./...
go test -v ./audit/...
```

Covered today: secret masking (including the 15/16/17-character boundary), path classification, context extraction edge cases (first line, missing file), triage with a mock LLM, malformed JSON from the model, invalid verdict values, confidence clamping, prompt-injection text in code context, cache behavior (offline results not cached, LLM results cached, model change invalidates the cache, failed calls not cached), and a check that prompts never contain a raw secret.

End-to-end check: scan a small repo of fake secrets, compare finding counts against plain `gitleaks git` / `gitleaks dir`, and search every output file (including the cache) for the real secret values. None should appear.

## Roadmap

1. **Phase 3: Risk and allowlist.** Risk score and level from secret type, path type, exposure and triage verdict; confirmed false positives written to `.gitleaksignore`; readable Markdown and HTML report.
2. **Phase 4: Auto-fix and recovery.** Patch that moves hardcoded secrets to environment variables, a pull request through the GitHub API, and rotation playbooks for common providers.
3. **Stretch goals.** Git history cleanup plan (`git filter-repo` commands with warnings), consent-based key liveness check, Semgrep integration for broader code vulnerabilities.

## Credits and License

SecretSentinel is a fork of [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) by Zachary Rice and contributors, released under the MIT License. See [LICENSE](LICENSE). Upstream documentation for the original commands and configuration is at [gitleaks.io](https://gitleaks.io).

Built for [Hackathon name], Cybersecurity & Privacy track.
