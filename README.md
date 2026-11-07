# SecretSentinel

**An AI-powered code security auditor built on top of [Gitleaks](https://github.com/gitleaks/gitleaks).**

Track: Cybersecurity & Privacy | Team: Git Secure  | Members: Pradnya Dange

> Gitleaks finds *possible* secrets. SecretSentinel answers the questions developers actually need answered: **Is it real? How dangerous is it? How do I stop the noise? How do I fix it? How do I recover?**

---

## Status

| Phase | Goal | Status |
|---|---|---|
| 1. Foundation | `gitleaks audit` command with enriched findings | **Done** |
| 2. AI triage | Verdict, confidence and reason per finding (Gemini, offline fallback, cache) | **Done** |
| 3. Risk, allowlist, reports | Risk ranking, safe allowlist suggestions, Markdown/HTML reports, rate-limit handling, multi-line secret masking | **Done** |
| 4a. Auto-fix | Preview and apply fixes on a separate review branch | **Done** |
| 4b. Recovery guidance | Rotation playbook and a generated pull request description | **Done** |
| 5. Demo and submission | Demo repo, slides, recording | In progress |

This README documents what exists **today (Phases 1 to 4b)**. See [Known Limitations](#known-limitations).

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
| No recovery guidance | Rotation playbook and a pull request description | 4b |

## Results So Far

On a small demo repository with 7 findings (3 real leaks and 4 decoys: a test file, a docs example, a test fixture and an `.env.example` placeholder):

- Gitleaks reports **7** alerts.
- AI triage labels **3 as `real_secret` and 4 as `likely_false_positive`**, matching hand labels.
- Risk ranking puts the three real leaks first (`critical`, `critical`, `high`) and the decoys at `info` or `low`.
- The generated allowlist suppresses the 4 decoys: a Gitleaks scan with it reports **3**, with 0 invalid-entry warnings, and none of the real secrets are suppressed.
- A second triage run costs 0 API calls (served from the cache).
- `--apply-fix` creates a review branch with one commit that changes `config.py` to read `os.environ["GITHUB_TOKEN"]`, stops tracking `.env`, adds `.env` to `.gitignore` and lists `STRIPE_KEY` in `.env.example` (names only). The fixed Python file runs when the variable is set, and the developer's own branch and uncommitted `.env` edits are left untouched.
- `--playbook` and `--pr-description` produce a rotation playbook (GitHub and Stripe sections, the history-only key marked "rotate the key", the four decoys shown only as `Ignored: 4`) and a pull request description whose environment variable names match the ones the fix actually wrote.
- A search of every output for the real secret values found nothing.

This is a small, hand-built set, and several decoys carry obvious hints in their path or comments, so treat it as a working demonstration and not an accuracy benchmark.

---

## How It Works (today) 
