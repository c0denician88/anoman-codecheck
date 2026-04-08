# Anoman CodeCheck

[![PyPI](https://img.shields.io/pypi/v/anoman-codecheck)](https://pypi.org/project/anoman-codecheck/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**AI-powered codebase security and quality scanner** with pre-built OWASP/NIST/ISO checklists, live CVE database lookup, supply chain scanning, and CI/CD-native output (SARIF, JUnit, GitLab, GitHub).

Uses Claude Opus via [Anoman AI](https://anoman.io) gateway with sovereign data routing.

## Quick Start

```bash
pip install anoman-codecheck
export ANOMAN_API_KEY="anm-sk-your-key-here"
anoman-codecheck scan ./my-project
```

---

## Setup Guide

### Step 1: Get an Anoman AI Account

1. Go to [https://app.anoman.io](https://app.anoman.io)
2. Click **"Create Account"**
3. Sign up with **Google**, **GitHub**, or **email + password**
4. Verify your email (check inbox for verification link)

### Step 2: Create an API Key

1. After signing in, go to **API Keys** in the sidebar
2. Click **"Create Key"**
3. Fill in:
   - **Name**: e.g. `codecheck-scanner`
   - **Tier**: `Team` or higher (for Bedrock sovereign access)
   - **Region**: `sg` (Singapore) or `id` (Indonesia)
   - **Region Preference** (optional):
     - `any` — route to any provider (fastest)
     - `sg_only` — data stays in Singapore (PDPA compliant)
     - `id_only` — data stays in Jakarta (UU PDP compliant)
4. Click **Create** and **copy the key** (shown only once)
5. The key looks like: `anm-sk-abc123...`

### Step 3: Configure

Set the API key as an environment variable:

```bash
# Linux / macOS
export ANOMAN_API_KEY="anm-sk-your-key-here"

# Windows (PowerShell)
$env:ANOMAN_API_KEY = "anm-sk-your-key-here"

# Windows (CMD)
set ANOMAN_API_KEY=anm-sk-your-key-here
```

Or pass it directly:

```bash
anoman-codecheck scan ./my-project --api-key "anm-sk-your-key-here"
```

### Choosing a Model and Region

The `--model` flag controls which AI model scans your code and **where your data is processed**:

| Model | AI Engine | Data Location | Compliance | Best For |
|-------|-----------|--------------|------------|---------|
| `claude-opus-bedrock-sg` | Claude Opus 4.6 | **Singapore** | PDPA | **Recommended** — most thorough, sovereign SG |
| `claude-opus-bedrock-id` | Claude Opus 4.6 | **Jakarta** | UU PDP | Indonesian data residency |
| `claude-sonnet-bedrock-sg` | Claude Sonnet 4.6 | **Singapore** | PDPA | Faster, cheaper, good accuracy |
| `claude-haiku-bedrock-sg` | Claude Haiku 4.5 | **Singapore** | PDPA | Fastest, cheapest, quick scans |
| `claude-sonnet-bedrock-id` | Claude Sonnet 4.6 | **Jakarta** | UU PDP | Fast + Indonesian residency |
| `claude-opus` | Claude Opus 4.6 | US (Virginia) | None | No data residency requirement |
| `claude-sonnet` | Claude Sonnet 4.6 | US (Virginia) | None | Fast, no residency requirement |

```bash
# Sovereign scan — data stays in Singapore
anoman-codecheck scan ./my-project --model claude-opus-bedrock-sg

# Sovereign scan — data stays in Jakarta
anoman-codecheck scan ./my-project --model claude-opus-bedrock-id

# Fast scan — less thorough but 5x faster
anoman-codecheck scan ./my-project --model claude-haiku-bedrock-sg

# US processing — cheapest, no data residency
anoman-codecheck scan ./my-project --model claude-sonnet
```

---

## Run Without Installing (from source)

No pip install needed — clone and run directly:

```bash
# Clone the repo
git clone https://github.com/c0denician88/anoman-codecheck
cd anoman-codecheck

# Install only the dependency (httpx)
pip install httpx

# Set your API key
export ANOMAN_API_KEY="anm-sk-your-key-here"

# Run directly with Python
python -m anoman_codecheck scan /path/to/your/project

# Or run the scanner module directly
python anoman_codecheck/scanner.py scan /path/to/your/project

# All flags work the same way
python -m anoman_codecheck scan ./my-project --type api --model claude-opus-bedrock-sg
python -m anoman_codecheck checklists
python -m anoman_codecheck checklist owasp-api --export
```

### One-liner (no clone needed)

```bash
# Download and run in one command
pip install httpx && \
  git clone https://github.com/c0denician88/anoman-codecheck /tmp/codecheck && \
  ANOMAN_API_KEY="anm-sk-..." python -m /tmp/codecheck/anoman_codecheck scan ./my-project
```

---

## Features

- **AI SAST** - Claude Opus analyzes for security vulns, credential leaks, quality issues
- **Pre-built Checklists** - OWASP API/Web Top 10, NIST SP 800-53, ISO 27001, Infra, Mobile (45+ checks)
- **Custom Checklists** - Export, edit, and use your own JSON checklists
- **Live CVE Lookup** - Queries OSV.dev on every scan for latest vulnerabilities
- **Supply Chain Scan** - Parses requirements.txt, package.json, pyproject.toml, go.mod
- **CI/CD Output** - SARIF, JUnit XML, GitLab Code Quality, GitHub annotations
- **CI Gating** - Exit code 1 on critical/high findings
- **Sovereign Routing** - Data stays in Singapore (PDPA) or Jakarta (UU PDP)

## Usage

```bash
anoman-codecheck scan ./my-project --type api          # Auto-select API checklists
anoman-codecheck scan ./my-project --checklist owasp-api  # Specific checklist
anoman-codecheck scan ./my-project --custom-checklist my-checks.json
anoman-codecheck scan ./my-project --output sarif --output-file results.sarif
anoman-codecheck scan ./my-project --fail-on critical   # CI gate
anoman-codecheck checklists                             # List all checklists
anoman-codecheck checklist owasp-api --export           # Export for customization
```

## Checklists

| Name | Framework | Items | Types |
|------|-----------|-------|-------|
| owasp-api | OWASP API Security Top 10 (2023) | 10 | api, backend |
| owasp-web | OWASP Web Top 10 (2021) | 10 | backend, frontend |
| nist | NIST SP 800-53 Rev 5 | 7 | api, backend, infra |
| iso27001 | ISO 27001:2022 Annex A | 6 | api, backend, frontend |
| infra | Docker + Terraform | 7 | infra |
| mobile | OWASP MASVS 2.0 | 5 | mobile |

Auto-selection: --type api = owasp-api + nist + iso27001

## CI/CD Integration

### GitHub Actions (SARIF)
```yaml
- run: pip install anoman-codecheck
- run: anoman-codecheck scan . --output sarif --output-file results.sarif --fail-on high
  env:
    ANOMAN_API_KEY: ${{ secrets.ANOMAN_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI
```yaml
script:
  - pip install anoman-codecheck
  - anoman-codecheck scan . --output gitlab --output-file gl-code-quality-report.json
artifacts:
  reports:
    codequality: gl-code-quality-report.json
```

### Jenkins (JUnit)
```groovy
sh 'anoman-codecheck scan . --output junit --output-file results.xml --fail-on critical'
junit 'results.xml'
```

## Output Formats

| Format | Flag | CI Support |
|--------|------|------------|
| Text | --output text | Terminal |
| JSON | --output json | Any |
| SARIF 2.1.0 | --output sarif | GitHub, Azure DevOps, VS Code |
| JUnit XML | --output junit | Jenkins, GitLab, CircleCI |
| GitLab Code Quality | --output gitlab | GitLab MR widget |
| GitHub Annotations | --output github | GitHub PR inline |

## Contributing

```bash
git clone https://github.com/c0denician88/anoman-codecheck
cd anoman-codecheck
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT - Built by [Anoman AI](https://anoman.io)
