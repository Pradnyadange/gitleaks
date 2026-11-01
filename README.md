# SecretSentinel

**An AI-powered code security auditor built on top of [Gitleaks](https://github.com/gitleaks/gitleaks).**

Track: Cybersecurity & Privacy | Team: [Team name] | Members: [Name] · [Name] · [Name]

> Gitleaks finds *possible* secrets. SecretSentinel answers the questions developers actually need answered: **Is it real? How dangerous is it? How do I stop the noise? How do I fix it?**

---

## Status

| Phase | Goal | Status |
|---|---|---|
| 1. Foundation | `gitleaks audit` command with enriched findings | **Done** |
| 2. AI triage | Verdict, confidence and reason per finding (Gemini, offline fallback, cache) | **Done** |
| 3. Risk, allowlist, reports | Risk ranking, safe allowlist suggestions, Markdown/HTML reports, rate-limit handling, multi-line secret masking | **Done** |
| 4a. Auto-fix | Preview and apply fixes on a separate review branch | **Done** (extra tests for refusal cases in progress) |
| 4b. Recovery guidance | Rotation playbooks and a generated pull request description | Planned |
| 5. Demo and submission | Demo repo, slides, recording | Planned |

This README documents what exists **today (Phases 1 to 4a)**. Anything marked Planned is not implemented. See [Known Limitations](#known-limitations).

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
| Output is a raw list of matches | Enriched findings: masked secret, code context, path type, history-only flag | 1 |
| Cannot tell a real key from a placeholder | AI triage: verdict, confidence, reason | 2 |
| All findings look equally urgent | Risk score and level, findings ranked by risk | 3 |
| Allowlists are written by hand | Suggested allowlist built from high-confidence AI false positives | 3 |
| Output is raw JSON for experts | Markdown and HTML reports | 3 |
| Private keys span many lines | Multi-line secrets are fully redacted | 3 |
| Detects but never fixes | Auto-fix on a review branch (env vars, `.env.example`, `.gitignore`) | 4a |
| No recovery guidance | Rotation playbooks and a pull request description | 4b (planned) |

## Results So Far

On a small demo repository with 7 findings (3 real leaks and 4 decoys: a test file, a docs example, a test fixture and an `.env.example` placeholder):

- Gitleaks reports **7** alerts.
- AI triage labels **3 as `real_secret` and 4 as `likely_false_positive`**, matching hand labels.
- Risk ranking puts the three real leaks first (`critical`, `critical`, `high`) and the decoys at `info` or `low`.
- The generated allowlist suppresses the 4 decoys: a Gitleaks scan with it reports **3**, with 0 invalid-entry warnings, and none of the real secrets are suppressed.
- A second triage run costs 0 API calls (served from the cache).
- `--apply-fix` creates a review branch with one commit that changes `config.py` to read `os.environ["GITHUB_TOKEN"]`, stops tracking `.env`, adds `.env` to `.gitignore` and lists `STRIPE_KEY` in `.env.example` (names only). The fixed Python file runs when the variable is set, and the developer's own branch and uncommitted `.env` edits are left untouched. A search of every output for the real secret values found nothing.

This is a small, hand-built set, and several decoys carry obvious hints in their path or comments, so treat it as a working demonstration and not an accuracy benchmark.

---

## How It Works (today)

```
Repo or folder
   -> Gitleaks scan (unchanged engine)
   -> Enrichment: masked secret, code context, path type, history-only flag
   -> Triage: Gemini verdict (or offline heuristics), cached by fingerprint
   -> Risk score and level, sorted highest first
   -> Optional outputs: JSON, suggested allowlist, Markdown/HTML report
   -> Optional fix: preview, or a review branch built in a separate git worktree
```

## Quick Start

Requires [Go](https://go.dev/dl/) and, for `--fix`, `git` on your PATH.

```bash
git clone https://github.com/Pradnyadange/gitleaks.git
cd gitleaks
go build -o gitleaks .
```

**1. Enrich findings only (no AI, no network):**

```bash
./gitleaks audit --mode git ./path/to/repo --audit-output audit-findings.json
./gitleaks audit --mode dir ./path/to/project
```

**2. Triage with offline heuristics only:**

```bash
./gitleaks audit --mode git ./path/to/repo --triage --offline
```

**3. Triage with Gemini:**

```bash
export GEMINI_API_KEY="..."              # PowerShell: $env:GEMINI_API_KEY = "..."
export GEMINI_MODEL="gemini-2.5-flash"   # or pass --gemini-model
./gitleaks audit --mode git ./path/to/repo --triage
```

List the models your key can use and pick a stable (non-preview) Flash model:

```powershell
Invoke-RestMethod -Uri "https://generativelanguage.googleapis.com/v1beta/models" `
  -Headers @{"x-goog-api-key" = $env:GEMINI_API_KEY} |
  Select-Object -ExpandProperty models |
  Where-Object { $_.supportedGenerationMethods -contains "generateContent" } |
  Select-Object name
```

**4. Allowlist suggestions and a report:**

```bash
./gitleaks audit --mode git ./path/to/repo --triage \
  --generate-allowlist --generate-report --report-format html --report-output audit-report.html
```

**5. Preview a fix, then apply it to a review branch:**

```bash
./gitleaks audit --mode git ./path/to/repo --triage --fix          # preview, writes nothing
./gitleaks audit --mode git ./path/to/repo --triage --apply-fix    # creates a local review branch
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
| `--triage-dry-run` | `false` | Print the exact prompts that would be sent, send nothing, no key needed |
| `--gemini-model` | env `GEMINI_MODEL` | Gemini model name. No default is hard-coded |
| `--triage-concurrency` | `3` | Parallel triage workers |
| `--triage-rpm` | `0` (unlimited) | Maximum requests per minute, to stay under free-tier limits |
| `--max-findings` | `50` | Maximum findings to triage per run |
| `--triage-context-lines` | `10` | Context lines included in the prompt (applies only with `--triage`) |
| `--generate-allowlist` | `false` | Write suggested allowlist entries |
| `--allowlist-output` | `.gitleaksignore.suggested` | Where to write them |
| `--allowlist-min-confidence` | `0.8` | Minimum LLM confidence for an entry |
| `--allowlist-dry-run` | `false` | Print entries without writing |
| `--generate-report` | `false` | Write a summary report |
| `--report-format` | `markdown` | `markdown` or `html` |
| `--report-output` | `audit-report.md` | Report path |
| `--fix` | `false` | Preview fixes. Writes nothing |
| `--apply-fix` | `false` | Create a local review branch with the fixes (implies `--fix`) |
| `--fix-include-review` | `false` | Also fix findings triaged as `needs_review` |
| `--fix-branch` | automatic | Name of the review branch. A number is appended if it already exists |

Existing Gitleaks flags (`--config`, `--baseline-path`, `--gitleaks-ignore-path`) still apply. `audit --help` lists every flag in your build.

> Note: `--report-format` on `audit` has the same name as a global Gitleaks flag. Check `audit --help` if you want to confirm which one applies in your build.

### Environment variables

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Read only from the environment and sent in the `x-goog-api-key` header. Never a flag, never logged |
| `GEMINI_MODEL` | Model name used when `--gemini-model` is not set |

Running `--triage` without `--offline` and without a key or model exits with a clear error. It does not silently fall back to heuristics. `--triage-dry-run` needs neither.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No leaks found |
| `1` | Leaks found, or an error occurred (same as upstream Gitleaks) |

---

## Auto-Fix (Phase 4a)

`--fix` previews and `--apply-fix` applies. The design goal is that **a fix can never damage the developer's working copy.**

### What gets fixed

| Target | Change |
|---|---|
| Python (`.py`) | The string literal containing the secret becomes `os.environ["NAME"]`, and `import os` is added once if missing |
| JavaScript / TypeScript (`.js .jsx .ts .tsx .mjs .cjs`) | The literal becomes `process.env.NAME` |
| Dotenv files (`.env`, `.env.*`, except `.env.example`, `.env.sample`, `.env.template`) | The file is **not edited**. It is removed from git tracking on the review branch, `.env` is added to `.gitignore`, and `KEY=` (names only, never values) is added to `.env.example` unless that key is already listed |

`NAME` is taken from the variable the secret is assigned to, converted to `UPPER_SNAKE_CASE`. For example `GITHUB_TOKEN = "..."` stays `GITHUB_TOKEN`, and `stripeKey = "..."` becomes `STRIPE_KEY`. The rule ID is used only when no name can be found. Names are kept unique within a file.

### What is never fixed automatically

Each of these is listed in the preview with a reason, and is left for a human:

- findings that are not `real_secret` (or `needs_review` unless `--fix-include-review` is set)
- secrets that exist only in git history because the file was later deleted: rotate the key
- multi-line secrets such as private keys
- secrets embedded in a larger string, such as a URL or connection string
- files in other languages
- untracked files, and any path that resolves outside the repository

### How `--apply-fix` stays safe

- The fix is built in a **separate `git worktree`**. Your current branch, index, working tree and real `.env` are never touched, and uncommitted edits to tracked files are not an obstacle.
- Fixes are based on the **committed** state of the repository.
- Before editing, each file is re-read and the secret must appear on the expected line exactly once, otherwise the finding is skipped. Line endings (CRLF or LF) and file permissions are preserved.
- Only the files that changed are added to the commit. Nothing is pushed or merged.
- The worktree is always removed afterwards. If anything fails after the branch is created, the branch is deleted too.
- The review branch is named `secretsentinel/remediation`, with a number appended if that name already exists.
- Everything printed (previews, errors, git output) is passed through a helper that replaces any raw secret with its masked form. The commit message lists the file, rule and variable name per fix, and never secret material.

After applying, review with `git diff <your-branch>...<fix-branch>` and roll back with `git branch -D <fix-branch>`.

> **The diff shows the old secret.** The removed line in the review branch's diff contains the original value, which is unavoidable. The secret is already in git history, so **rotating the credential is what actually protects you.** Removing it from code does not remove it from history.

---

## Output

Illustrative record (values shortened; field names follow the real output):

```json
{
  "rule_id": "stripe-access-token",
  "file": ".env",
  "start_line": 1,
  "end_line": 1,
  "commit": "9e77c95...",
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
  },
  "risk_score": 84,
  "risk_level": "critical"
}
```

The raw secret is held in memory only while the fix engine needs it. It is excluded from JSON output, prompts and reports.

Findings are sorted by risk score, highest first. A triage summary is printed after each triage run:

```
=== SECRET SENTINEL TRIAGE SUMMARY ===
Total Findings Processed: 7
Verdicts:   real_secret: 3, likely_false_positive: 4
Sources:    llm: 7
API Calls Made: 0
Cache Hits: 7
LLM Successes: 0
LLM Failures: 0
Retries after 429: 0
```

### Triage verdicts

| Verdict | Meaning |
|---|---|
| `real_secret` | Looks like a genuine credential in production-relevant code |
| `likely_false_positive` | Placeholder, test fixture, documentation example, hash, ID, or non-secret |
| `needs_review` | Not enough evidence. The model is told to be conservative |

Each result has a `confidence` (0 to 1, clamped), a one-sentence `reason`, a `source` (`llm` or `heuristic`) and a `cached` flag.

### Risk levels

Findings get a 0 to 100 score and a level: `critical`, `high`, `medium`, `low` or `info`. The score uses path type, history-only status, entropy and the triage verdict, and it also works with no triage at all. An AI-confirmed false positive maps to `info`. Each score carries the factors that produced it and a short impact statement.

### Offline heuristics

Used by `--offline` and as the automatic fallback when an LLM call fails. They never output `real_secret`:

- test, example or docs paths -> `likely_false_positive`
- placeholder-style text in the secret or context (`example`, `changeme`, `dummy`, `placeholder`) -> `likely_false_positive`
- everything else -> `needs_review`

### Cache

Results are cached in `.secretsentinel-cache.json` so reruns cost nothing.

- Only LLM results are cached. Heuristic results are never cached or served as cache hits.
- The key is fingerprint + model name + a prompt version, so changing the model or prompt invalidates old entries.
- Failed LLM calls fall back to heuristics, are not cached, and are counted as failures.

### Rate limits

The Gemini free tier allows only a few requests per minute. On HTTP 429 the client waits the `retryDelay` Google returns before retrying, and only 429 and 5xx responses are retried. Use `--triage-rpm 4` and `--triage-concurrency 1` to stay under the limit, and run triage ahead of time so reruns come from the cache.

### Suggested allowlist

`--generate-allowlist` writes **per-finding fingerprints**, one per line, in the format Gitleaks expects, each with a `# SecretSentinel:` comment giving the reason.

- Only findings with `source: llm`, verdict `likely_false_positive` and confidence at or above the threshold qualify. Heuristic, `real_secret` and `needs_review` findings never do.
- Output goes to `.gitleaksignore.suggested` by default. Review it, then merge it into your real `.gitleaksignore` yourself. Nothing is activated automatically.
- Entries are appended, de-duplicated and backed up once (`.bak`) before the first change. Reason text is sanitized so it cannot inject extra lines.
- Nothing is written when no finding qualifies, and `--allowlist-dry-run` shows what would be added.

### Reports

`--generate-report` writes a Markdown or HTML report of the ranked findings (rule, file, risk level, score, verdict, source). The HTML report is one self-contained file, rendered through `html/template` so code context is escaped, with no scripts and no external requests. Reports contain masked values only.

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

Sending code to an LLM is itself a risk, so SecretSentinel sends as little as possible:

- **Raw secrets never reach the prompt.** Prompts contain the masked value, the secret length and redacted context. A test fails if a prompt contains a raw secret.
- **Multi-line secrets are fully redacted.** For private keys and similar, every line of the key (including the BEGIN and END lines) is replaced with a single redaction marker in context, prompts and reports. This was found by scanning this project's own history with SecretSentinel, which showed that an earlier version let a key body through.
- **Short secrets reveal nothing.** Partial masking (first 4 characters, `****`, last 2) applies only to single-line secrets of 16 or more characters. Shorter ones are fully masked.
- **Small context window.** 10 lines by default for prompts (`--triage-context-lines`).
- **Free-tier note.** Google states that content sent through the free Gemini API tier may be used to improve its products. Use a paid tier or `--offline` for sensitive repositories.
- **Prompt-injection defense.** Code context is treated as untrusted data. The system prompt tells the model to ignore instructions inside it, and every response is validated (allowed verdicts, clamped confidence, truncated reason).
- **Dry run.** `--triage-dry-run` prints exactly what would be sent so you can inspect it first.
- **Key handling.** The API key is read only from the environment and is never logged. Rotate any key that has ever been pasted into a chat, file or commit.
- **Safe failure.** Bad model output or API failure falls back to heuristics and the scan continues.
- **Fixes never touch your working copy** (see [Auto-Fix](#auto-fix-phase-4a)).

Never commit audit output. `*-audit.json`, `audit-findings.json`, `.secretsentinel-cache.json`, `.gitleaksignore.suggested`, `*.bak` and `.env` are in `.gitignore`.

## Known Limitations

- **AI verdicts can be wrong.** In testing, a decoy `.env.example` that held a value in real key format was labeled a false positive because of a "placeholder" comment. Allowlist suggestions are therefore written to a separate file for human review, and nothing is allowlisted from heuristic verdicts.
- **Auto-fix is deliberately narrow.** It handles Python, JS/TS and dotenv files only. Everything else, including history-only secrets, multi-line keys and secrets inside URLs, is reported for manual fixing.
- **A fix does not make a secret safe.** The credential remains in git history and must be rotated. Rotation guidance is planned for Phase 4b.
- **Fixes are based on committed state.** Uncommitted changes are not included in the review branch.
- **Free-tier rate limits.** Gemini's free tier can reject bursts of requests. Failed calls fall back to heuristics and are not cached.
- **Small evaluation set.** Accuracy and fix behavior have been checked on small demo repositories only.

## Project Structure (SecretSentinel additions)

```
cmd/
  audit.go            # `audit` command, flags, JSON output, summaries
audit/
  types.go            # EnrichedFinding and Triage structs
  mask.go             # secret masking (16-character boundary, multi-line aware)
  pathtype.go         # path classification
  context.go          # code context extraction and redaction
  llm.go              # LLMClient interface
  gemini.go           # Gemini REST client (net/http, retry-after handling)
  ratelimit.go        # requests-per-minute limiter
  prompt.go           # system prompt and user prompt builder
  heuristics.go       # offline fallback triage
  triage.go           # worker pool, cache, response validation
  dryrun.go           # prompt preview with no credentials or network
  risk.go             # risk score, level, factors, impact
  allowlist_safe.go   # safe allowlist suggestion writer
  report.go           # Markdown and HTML reports
  fix.go              # fix engine: eligibility, preview, apply
  fix_git.go          # git worktree, branch, commit operations
  fix_lang.go         # Python, JS/TS and dotenv patchers
  fix_naming.go       # environment variable name extraction
  fix_sanitizer.go    # replaces raw secrets in anything printed
  *_test.go           # unit tests
```

The Gitleaks detection engine (`detect/`, `sources/`, `config/`) is **not modified**.

## Testing

```bash
go build ./...
go test -v ./audit/...
```

Covered today: secret masking (including the 15/16/17-character boundary) and multi-line key redaction, path classification, context extraction edge cases, triage with a mock LLM (valid and malformed JSON, invalid verdicts, confidence clamping, prompt injection), cache behavior (offline not cached, LLM cached, model change invalidates, failures not cached), dry run (no credentials, no cache writes), 429 retry-delay parsing and non-retry of other 4xx errors, rate limiter spacing, risk scoring, allowlist safety (eligibility, injection, dedupe, backup, dry run), report generation (sorting, HTML escaping, no raw secrets), and the fix engine (Python, JS and CRLF patches, `import os` added once, environment variable naming, dotenv handling, review branch naming, the user's working tree and uncommitted `.env` left untouched, no raw secret in output or commit messages).

End-to-end check: scan a repo of fake secrets, compare finding counts with plain `gitleaks git` / `gitleaks dir`, and search every output file (including the cache, reports and fix output) for the real secret values. None should appear.

## Roadmap

1. **Phase 4b: Recovery guidance.** Offline rotation playbooks for common providers (GitHub, AWS, Stripe), and a generated pull request description with a "before you merge" checklist.
2. **Stretch goals.** Git history cleanup plan (`git filter-repo` commands with warnings), consent-based key liveness check, an opt-in command that opens the pull request, Semgrep integration.

## Credits and License

SecretSentinel is a fork of [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) by Zachary Rice and contributors, released under the MIT License. See [LICENSE](LICENSE). Upstream documentation is at [gitleaks.io](https://gitleaks.io).

Built for [Hackathon name], Cybersecurity & Privacy track.
