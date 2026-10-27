# SecretSentinel

**An AI-powered code security auditor built on top of [Gitleaks](https://github.com/gitleaks/gitleaks).**


> Gitleaks finds *possible* secrets. SecretSentinel is being built to answer the questions developers actually need answered: **Is it real? How dangerous is it? How do I fix it? How do I recover?**

---

## Status

| Phase | Goal | Status |
|---|---|---|
| 1. Foundation | `gitleaks audit` command with enriched findings | **Done** |
| 2. AI triage | Verdict, confidence and reason for each finding (Gemini + offline fallback) | Planned |
| 3. Risk and allowlist | Risk ranking, auto-generated `.gitleaksignore`, Markdown report | Planned |
| 4. Auto-fix and recovery | Fix pull request, rotation playbooks | Planned |
| 5. Demo and submission | Leaky demo repo, tests, final presentation | Planned |

This README documents what exists **today (Phase 1)**. Everything marked Planned is not yet implemented.

---

## The Problem

- Developers accidentally commit API keys, tokens and passwords, and the secret stays in git history even after the file is deleted.
- Automated bots scan public repositories and can find exposed credentials within minutes.
- One exposed key can open servers, databases and cloud accounts, putting user data at risk.
- Small teams have no security engineer, no time to review every commit, and suffer alert fatigue from noisy scanners.

## What Gitleaks Already Does (and we do not re-claim)

Gitleaks provides git-history, directory and stdin scanning, a regex and entropy rule engine, allowlists (`.gitleaksignore`, `gitleaks:allow`), baselines, JSON/SARIF/CSV/JUnit reports, redaction, and CI exit codes. SecretSentinel uses it unchanged as the detection engine.

## What SecretSentinel Adds

| Gap in Gitleaks alone | SecretSentinel feature | Phase |
|---|---|---|
| Output is a raw list of matches | Enriched findings: code context, masked secret, path type, history-only flag | 1 (done) |
| Cannot tell a real key from a placeholder | AI context triage with verdict, confidence, reason | 2 |
| All findings look equally urgent | Risk scoring and ranking | 3 |
| Allowlists are written by hand | Auto-generated allowlist from confirmed false positives | 3 |
| Detects but never fixes | Auto-fix pull request (env var, `.env.example`, `.gitignore`) | 4 |
| No recovery guidance | Provider-specific key rotation playbook | 4 |

---

## What Works Today: `gitleaks audit`

The `audit` command runs a normal Gitleaks scan and turns every finding into an **enriched finding** written to a JSON file. No AI or network calls are made in Phase 1.

Each enriched finding includes:

- **Masked secret.** The raw secret is never written unless you opt in.
- **Code context.** Lines before and after the finding, with the secret redacted.
- **Path type.** A heuristic label for where the finding lives.
- **History-only flag.** Whether the file no longer exists in the working tree (the secret survives only in git history).
- The usual Gitleaks metadata: rule, file, line, commit, author, date, entropy, fingerprint.

### Quick start

Requires [Go](https://go.dev/dl/) installed.

```bash
git clone https://github.com/Pradnyadange/gitleaks.git
cd gitleaks
go build -o gitleaks .
```

Scan a directory:

```bash
./gitleaks audit --mode dir ./path/to/project --audit-output audit-findings.json
```

Scan full git history:

```bash
./gitleaks audit --mode git ./path/to/repo --audit-output audit-findings.json
```

On Windows (PowerShell), without building:

```powershell
go run main.go audit --mode dir "D:\path\to\project" --audit-output audit-findings.json
go run main.go audit --mode git "D:\path\to\repo"    --audit-output audit-findings.json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `git` | `git` scans commit history, `dir` scans files on disk |
| `--audit-output` | `audit-findings.json` | Output JSON file path |
| `--context-lines` | `20` | Lines of code context before and after each finding |
| `--include-raw-secret` | `false` | Include raw secrets in the output. **Leave off** unless you fully control the output file |

Existing Gitleaks flags such as `--config`, `--baseline-path` and `--gitleaks-ignore-path` continue to apply.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No leaks found |
| `1` | Leaks found, or an error occurred (same as upstream Gitleaks) |

### Example output

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
  "masked_secret": "sk_l****Ho",
  "code_context": [
    "STRIPE_KEY=sk_l****Ho"
  ]
}
```

### Secret masking

To keep credentials out of reports and logs, secrets are masked: first 4 characters, then `****`, then last 2 characters. Secrets shorter than 10 characters are fully masked. Raw secret values inside `code_context` are replaced with the masked form. The raw secret is only written when `--include-raw-secret` is set.

> Planned change: partial masking will apply only to secrets of 16 or more characters, so short secrets reveal nothing. This matters before any data is sent to an LLM in Phase 2.

### Path types

Files are classified with simple path heuristics so later phases can weigh risk:

| Path type | Matches |
|---|---|
| `test` | `/test/`, `test_`, `_test.go`, `specs/` |
| `example` | `example`, `sample`, `demo` |
| `docs` | `doc/`, `.md`, `.rst`, `.txt` |
| `vendor` | `vendor/`, `node_modules/`, `third_party/` |
| `config` | `config/`, `.env`, `.json`, `.yml`, `.yaml`, `.toml`, `.ini` |
| `source` | everything else |

### Context extraction

- **`dir` mode:** context is read from disk.
- **`git` mode:** context is read with `git show <commit>:<path>`, so it works for files that were later deleted. If the lookup fails, `code_context` is left empty with a warning and the scan continues.

---

## Project Structure (SecretSentinel additions)

```
cmd/
  audit.go            # `audit` cobra command, flags, JSON output
audit/
  types.go            # EnrichedFinding struct
  mask.go             # secret masking
  pathtype.go         # path classification
  context.go          # code context extraction and redaction
  audit_test.go       # unit tests
```

The Gitleaks detection engine (`detect/`, `sources/`, `config/`) is **not modified**. SecretSentinel layers on top of it, which keeps upstream behavior intact.

## Testing

```bash
go build ./...
go test -v ./audit/...
```

Unit tests cover masking (empty, short and long secrets), path classification, and context extraction edge cases (finding on the first line, last line, missing file).

To verify end to end, scan a small repo containing fake secrets and compare finding counts with plain `gitleaks dir` / `gitleaks git`. Counts should match, and no raw secret should appear in the audit file.

## Security Notes

- Never commit audit output. Add `*-audit.json`, `audit-findings.json` and `.env` to `.gitignore`.
- Use only fake or already-rotated credentials in demos and tests.
- Code context is untrusted input. Later phases treat it strictly as data before it reaches an LLM.
- Planned phases will send only masked values to any LLM, never raw secrets.

## Roadmap

1. **Phase 2: AI triage.** `--triage` adds `verdict` (`real_secret`, `likely_false_positive`, `needs_review`), `confidence` and `reason` per finding, with an offline heuristic fallback and a local cache.
2. **Phase 3: Risk and allowlist.** Risk ranking from secret type, path type and exposure; false positives written to `.gitleaksignore`; readable Markdown report.
3. **Phase 4: Auto-fix and recovery.** Patch that moves hardcoded secrets to environment variables, a pull request through the GitHub API, and rotation playbooks for common providers.
4. **Stretch goals.** Git history cleanup plan (`git filter-repo` commands with warnings), key liveness check (consent-based, read-only), Semgrep integration for broader code vulnerabilities.

## Credits and License

SecretSentinel is a fork of [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) by Zachary Rice and contributors, released under the MIT License. See [LICENSE](LICENSE). Upstream documentation for the original commands and configuration is at [gitleaks.io](https://gitleaks.io).

Built for [Hackathon name], Cybersecurity & Privacy track.
