# Anoman CodeCheck

[![PyPI](https://img.shields.io/pypi/v/anoman-codecheck)](https://pypi.org/project/anoman-codecheck/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**AI-powered codebase security & quality scanner.** Uses Claude Opus via [Anoman AI](https://anoman.io) gateway with sovereign data routing (Singapore PDPA / Jakarta UU PDP) to scan your code for vulnerabilities, credential leaks, quality issues, and compliance concerns.

---

## What It Scans

| Category | Severity | Examples |
|----------|----------|---------|
| **Security Vulnerabilities** | CRITICAL/HIGH | SQL injection, XSS, command injection, SSRF, path traversal, OWASP Top 10 |
| **Credential Leaks** | CRITICAL | Hardcoded API keys, passwords, tokens, private keys, .env files with real values |
| **Code Quality** | MEDIUM | Unhandled exceptions, race conditions, memory leaks, dead code, anti-patterns |
| **Compliance** | LOW-MEDIUM | PII handling without encryption, logging sensitive data, missing audit trails |

---

## Why Use This Over Traditional SAST?

| Feature | Traditional SAST | Anoman CodeCheck |
|---------|-----------------|------------------|
| Detection method | Regex / AST patterns | Claude Opus AI reasoning |
| False positive rate | High (30-60%) | Low (~5-10%) |
| Context understanding | None — pattern matching | Full — understands business logic |
| Custom vulnerabilities | Needs rule authoring | Describes in natural language |
| Data residency | Runs locally | **Sovereign routing** — data stays in SG or ID |
| Setup time | Hours (rules, config) | **2 minutes** (just an API key) |

---

## Quick Start

### Step 1: Install

```bash
pip install anoman-codecheck
```

Or from source:

```bash
git clone https://github.com/c0denician88/anoman-codecheck
cd anoman-codecheck
pip install -e .
```

### Step 2: Get an Anoman API Key

1. Go to [https://app.anoman.io](https://app.anoman.io)
2. Sign up (Google, GitHub, or email)
3. Go to **API Keys** → **Create Key**
4. Select tier: **Team** or higher (for Bedrock sovereign access)
5. Set region preference: `sg_only` (Singapore/PDPA) or `id_only` (Jakarta/UU PDP)
6. Copy the key

### Step 3: Set Environment Variable

```bash
export ANOMAN_API_KEY="anm-sk-your-key-here"
```

### Step 4: Scan Your Codebase

```bash
# Scan current directory
anoman-codecheck scan .

# Scan a specific project
anoman-codecheck scan ./my-project

# Scan with Singapore sovereign routing (PDPA compliant)
anoman-codecheck scan ./my-project --model claude-opus-bedrock-sg

# Scan with Jakarta sovereign routing (UU PDP compliant)
anoman-codecheck scan ./my-project --model claude-opus-bedrock-id

# Output as JSON
anoman-codecheck scan ./my-project --output json --output-file results.json

# Scan with more files
anoman-codecheck scan ./my-project --max-files 100
```

---

## Full Usage

```
usage: anoman-codecheck scan [-h] [--api-key API_KEY] [--gateway GATEWAY]
                              [--model MODEL] [--region {any,sg_only,id_only}]
                              [--max-files MAX_FILES] [--output {text,json}]
                              [--output-file OUTPUT_FILE] path

positional arguments:
  path                  Path to the codebase to scan

optional arguments:
  --api-key             Anoman API key (or set ANOMAN_API_KEY env var)
  --gateway             Anoman gateway URL (default: https://api.anoman.io)
  --model               Model to use (default: claude-opus-bedrock-sg)
  --region              Data residency: any, sg_only, id_only
  --max-files           Maximum files to scan (default: 50)
  --output              Output format: text or json
  --output-file         Save results to file
```

---

## Example Output

```
Anoman CodeCheck v0.1.0
  Scanning: /home/user/my-project
  Model: claude-opus-bedrock-sg
  Gateway: https://api.anoman.io

  Collecting files...
  Found 23 scannable files
  Payload size: 45,230 chars

  Running AI security scan...
  Sending to https://api.anoman.io via model claude-opus-bedrock-sg...
  Response: HTTP 200 in 12.3s
  Tokens: 8432 in / 1205 out

============================================================
  ANOMAN CODECHECK — Security Scan Report
============================================================

  Summary:
    Total findings: 4
    Critical: 1
    High: 1
    Medium: 1
    Low: 1
    Clean files: 19

  Findings (4):
  --------------------------------------------------------

  [!] CRITICAL — credential
      File: config/database.py:15
      Hardcoded PostgreSQL password in connection string
      Fix: Move to environment variable or secret manager

  [!] HIGH — security
      File: api/users.py:42
      SQL query built with string concatenation (SQL injection risk)
      Fix: Use parameterized queries with SQLAlchemy

  [*] MEDIUM — quality
      File: services/payment.py:88
      Bare except clause catches all exceptions including SystemExit
      Fix: Catch specific exceptions (ValueError, httpx.HTTPError)

  [-] LOW — compliance
      File: middleware/logging.py:23
      Request body logged without PII redaction
      Fix: Mask sensitive fields before logging

  Scan metadata:
    Model: claude-opus-4-20250514
    Latency: 12.3s
    Tokens: 8432 in / 1205 out

============================================================
```

---

## Sovereign Data Routing

Your code is sent to the LLM for analysis. With Anoman's sovereign routing, you control **exactly where that data is processed**:

| Model | Data Location | Compliance | Multiplier |
|-------|--------------|------------|-----------|
| `claude-opus-bedrock-sg` | **Singapore** | PDPA | 0.8× |
| `claude-opus-bedrock-id` | **Jakarta** | UU PDP | 0.8× |
| `claude-opus` | US (Virginia) | None | 1.0× |

**For regulated industries:** Use `--model claude-opus-bedrock-sg` or `claude-opus-bedrock-id` to ensure your source code never leaves Southeast Asia during scanning.

---

## Supported File Types

The scanner processes these file extensions:

| Category | Extensions |
|----------|-----------|
| Python | `.py` |
| JavaScript/TypeScript | `.js`, `.ts`, `.tsx`, `.jsx` |
| Java/Kotlin | `.java`, `.kt` |
| Go | `.go` |
| Rust | `.rs` |
| Ruby | `.rb` |
| PHP | `.php` |
| C/C++ | `.c`, `.cpp`, `.h` |
| Swift | `.swift` |
| Scala | `.scala` |
| C# | `.cs` |
| Config | `.yaml`, `.yml`, `.json`, `.toml`, `.env`, `.ini`, `.cfg` |
| SQL | `.sql` |
| Shell | `.sh`, `.bash` |
| Docker | `.dockerfile` |
| Terraform | `.tf` |

Files larger than 100KB and directories like `node_modules`, `.git`, `dist`, `build` are automatically skipped.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  codecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install anoman-codecheck
      - run: anoman-codecheck scan . --output json --output-file scan-results.json
        env:
          ANOMAN_API_KEY: ${{ secrets.ANOMAN_API_KEY }}
      - name: Check for critical findings
        run: |
          critical=$(python -c "import json; d=json.load(open('scan-results.json')); print(d.get('summary',{}).get('critical',0))")
          if [ "$critical" -gt 0 ]; then
            echo "::error::Critical security findings detected!"
            exit 1
          fi
      - uses: actions/upload-artifact@v4
        with:
          name: security-scan
          path: scan-results.json
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install anoman-codecheck
    - anoman-codecheck scan . --output json --output-file scan-results.json
  variables:
    ANOMAN_API_KEY: $ANOMAN_API_KEY
  artifacts:
    reports:
      codequality: scan-results.json
```

---

## Programmatic Usage

```python
from anoman_codecheck.scanner import collect_files, build_scan_payload, scan_with_llm, print_report
from pathlib import Path

# Collect and scan
files = collect_files(Path("./my-project"), max_files=30)
payload = build_scan_payload(files)
result = scan_with_llm(
    code_payload=payload,
    api_key="anm-sk-your-key-here",
    model="claude-opus-bedrock-sg",  # Sovereign SG
)

# Print formatted report
print_report(result)

# Or process findings programmatically
for finding in result.get("findings", []):
    if finding["severity"] == "CRITICAL":
        print(f"CRITICAL: {finding['file']} — {finding['description']}")
```

---

## How It Works

```
Your Code → Anoman Gateway → Guardrails → Sovereign Bedrock (SG/ID) → Claude Opus → Analysis
                 ↓
         PII masking runs on YOUR code before it reaches the LLM
         (NIK, NRIC, email, phone numbers are redacted)
```

1. **File collection** — Scans your project directory, skips binaries/dependencies
2. **Payload building** — Concatenates source files with path headers
3. **Gateway routing** — Sends to Anoman AI gateway with your API key
4. **Guardrails** — PII masking runs on your code (protects credentials in transit)
5. **Sovereign routing** — Routes to Bedrock Singapore or Jakarta based on model choice
6. **AI analysis** — Claude Opus analyzes for security, quality, credentials, compliance
7. **Structured output** — Returns JSON findings with severity, file, line, recommendation

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANOMAN_API_KEY` | Your Anoman API key | Required |
| `ANOMAN_GATEWAY` | Gateway URL | `https://api.anoman.io` |

### Models Available

| Model | Provider | Location | Best For |
|-------|----------|----------|----------|
| `claude-opus-bedrock-sg` | Bedrock Singapore | PDPA sovereign | **Default — recommended** |
| `claude-opus-bedrock-id` | Bedrock Jakarta | UU PDP sovereign | Indonesian compliance |
| `claude-opus` | Anthropic Direct | US | No data residency requirement |
| `claude-sonnet-bedrock-sg` | Bedrock Singapore | PDPA sovereign | Faster, cheaper, less thorough |
| `claude-haiku-bedrock-sg` | Bedrock Singapore | PDPA sovereign | Quick scans, budget-friendly |

---

## Contributing

```bash
git clone https://github.com/c0denician88/anoman-codecheck
cd anoman-codecheck
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Credits

Built by [Anoman AI](https://anoman.io) — the first guarded LLM gateway with sovereign data routing for Southeast Asia. Scans are powered by Claude Opus via AWS Bedrock with PDPA/UU PDP data residency enforcement.

---

## License

MIT — use freely in commercial and open-source projects.
