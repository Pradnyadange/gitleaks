# SecretSentinel Audit Report

## Summary
- **Date:** 2026-11-04 01:30:50
- **Total Findings:** 3
- **Risk Levels:** Critical: 0, High: 3, Medium: 0, Low: 0, Info: 0
- **Verdicts:** Real Secret: 0, False Positive: 0, Needs Review: 0, N/A: 3

## Ranked Findings
| Rule ID | File | Risk Level | Score | Verdict | Source |
|---|---|---|---|---|---|
| generic-api-key | .env | high | 50 | N/A | N/A |
| private-key | audit-findings.json | high | 50 | N/A | N/A |
| private-key | gpt-researcher-audit.json | high | 50 | N/A | N/A |

## Detailed Findings
### Rule: generic-api-key (`.env:2`)
- **Masked Secret:** `sb_s****Yg`
- **Verdict & Reason:** N/A
- **Level & Factors:** high | Factors: Path type is configuration, Present in active working tree, High entropy value (>4.0)
- **Impact:** Exposed private cryptographic keys allow identity spoofing, decryption of secure traffic, and system compromise.
- **History:** Present in active working tree.
- **Code Context:**
  > `VITE_SUPABASE_URL=https://nsuzfpalpphomorfchub.supabase.co`
  > `VITE_SUPABASE_ANON_KEY=sb_s****Yg`
- **Recommended action:** rotate the credential, then remove it from code.

### Rule: private-key (`audit-findings.json:23`)
- **Masked Secret:** `[MULTI-LINE SECRET, 7 lines]`
- **Verdict & Reason:** N/A
- **Level & Factors:** high | Factors: Path type is configuration, Present in active working tree, High entropy value (>4.0)
- **Impact:** Exposed private cryptographic keys allow identity spoofing, decryption of secure traffic, and system compromise.
- **History:** Present in active working tree.
- **Code Context:**
  > `    "fingerprint": "gpt-researcher-audit.json:private-key:171",`
  > `    "rule_id": "private-key",`
  > `    "description": "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",`
  > `    "file": "gpt-researcher-audit.json",`
  > `    "start_line": 171,`
  > `    "end_line": 177,`
  > `    "entropy": 5.439846992492676,`
  > `    "masked_secret": "----****--",`
  > `    "secret_length": 440,`
  > `    "code_context": [`
  > `      "    \"description\": \"Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.\",",`
  > `      "    \"file\": \"ollama/ollama/id_ed25519\",",`
  > `      "    \"start_line\": 1,",`
  > `      "    \"end_line\": 7,",`
  > `      "    \"commit\": \"e1957fd129f54c2e04cb7ac2b0066b0c7717b20a\",",`
  > `      "    \"author\": \"ElishaKay\",",`
  > `      "    \"date\": \"2024-08-18T07:30:08Z\",",`
  > `      "    \"entropy\": 5.4816575,",`
  > `      "    \"masked_secret\": \"----****--\",",`
  > `      "    \"code_context\": [",`
  > `[REDACTED MULTI-LINE SECRET]`
  > `      "    ],",`
  > `      "    \"path_type\": \"source\",",`
  > `      "    \"in_history_only\": true",`
  > `      "  },"`
  > `    ],`
  > `    "path_type": "config",`
  > `    "in_history_only": false,`
  > `    "triage": {`
  > `      "verdict": "real_secret",`
  > `      "confidence": 1,`
  > `      "reason": "The code context explicitly contains the full content of an OpenSSH private key, including the '-----BEGIN OPENSSH PRIVATE KEY-----' and '-----END OPENSSH PRIVA",`
  > `      "source": "llm",`
  > `      "cached": false`
  > `    },`
- **Recommended action:** rotate the credential, then remove it from code.

### Rule: private-key (`gpt-researcher-audit.json:171`)
- **Masked Secret:** `[MULTI-LINE SECRET, 7 lines]`
- **Verdict & Reason:** N/A
- **Level & Factors:** high | Factors: Path type is configuration, Present in active working tree, High entropy value (>4.0)
- **Impact:** Exposed private cryptographic keys allow identity spoofing, decryption of secure traffic, and system compromise.
- **History:** Present in active working tree.
- **Code Context:**
  > `      "docker-compose up -- build",`
  > `      "",`
  > `      "\u003e **Step 3** -  from the frontend input box in localhost:3000, you can append any google search filter (such as filtering by domain names)"`
  > `    ],`
  > `    "path_type": "docs",`
  > `    "in_history_only": false`
  > `  },`
  > `  {`
  > `    "fingerprint": "e1957fd129f54c2e04cb7ac2b0066b0c7717b20a:ollama/ollama/id_ed25519:private-key:1",`
  > `    "rule_id": "private-key",`
  > `    "description": "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",`
  > `    "file": "ollama/ollama/id_ed25519",`
  > `    "start_line": 1,`
  > `    "end_line": 7,`
  > `    "commit": "e1957fd129f54c2e04cb7ac2b0066b0c7717b20a",`
  > `    "author": "ElishaKay",`
  > `    "date": "2024-08-18T07:30:08Z",`
  > `    "entropy": 5.4816575,`
  > `    "masked_secret": "----****--",`
  > `    "code_context": [`
  > `[REDACTED MULTI-LINE SECRET]`
  > `    ],`
  > `    "path_type": "source",`
  > `    "in_history_only": true`
  > `  },`
  > `  {`
  > `    "fingerprint": "0bb51fef6880592177ad521bd86e3d0716bd81be:multi_agents/gpt_researcher_nextjs/components/Langgraph/Langgraph.js:generic-api-key:12",`
  > `    "rule_id": "generic-api-key",`
  > `    "description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",`
  > `    "file": "multi_agents/gpt_researcher_nextjs/components/Langgraph/Langgraph.js",`
  > `    "start_line": 12,`
  > `    "end_line": 12,`
  > `    "commit": "0bb51fef6880592177ad521bd86e3d0716bd81be",`
  > `    "author": "ElishaKay",`
  > `    "date": "2024-07-05T04:20:44Z",`
- **Recommended action:** rotate the credential, then remove it from code.

