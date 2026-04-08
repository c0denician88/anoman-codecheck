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

## Why Anoman CodeCheck?

Traditional SAST tools and manual code reviews each solve part of the problem — but neither solves it completely. Anoman CodeCheck combines the depth of a senior security engineer's review with the speed and consistency of automation.

### The Problem

| Challenge | Traditional SAST | Manual Code Review |
|-----------|------------------|--------------------|
| Setup time | Hours to days (rules, exclusions, tuning) | Zero tooling, but needs scheduling |
| False positives | **High** — pattern matching triggers on safe code | Low — human judgment filters noise |
| Business logic flaws | Misses entirely — can't understand intent | **Catches** — human reads context |
| Novel vulnerabilities | Only finds known patterns | Can reason about new attack vectors |
| Compliance mapping | Basic (CWE only) | Depends on reviewer's knowledge |
| Supply chain risks | Separate tool (Snyk, Dependabot) | Usually skipped |
| Speed at scale | Fast on large codebases | **Bottleneck** — days/weeks for large reviews |
| Consistency | Deterministic but rigid | Varies by reviewer skill and fatigue |
| CI/CD integration | Good (SARIF, JUnit) | Manual gate — blocks pipelines |
| Cost | $50–500+/month per repo | $150–300/hour for specialist reviewers |
| Data residency | Data sent to US/EU vendor cloud | In-house only |

### How Anoman CodeCheck Is Different

Anoman CodeCheck uses **Claude Opus** (one of the most capable reasoning models) to perform code review the way a senior security engineer would — reading the code, understanding business logic, tracing data flows, and reasoning about attack surfaces — but in **minutes instead of days**.

**What you get:**

- **Understands context, not just patterns.** An LLM reads your code like a human reviewer. It catches business logic flaws, insecure design patterns, and subtle vulnerabilities that regex-based SAST tools miss entirely.
- **Zero configuration.** Point it at a directory and scan. No rules to write, no exclusions to tune, no training data to maintain. The AI already knows what to look for.
- **Framework-aware compliance.** Every finding maps to a specific OWASP, NIST SP 800-53, ISO 27001, or CWE control ID. Your auditors get structured evidence, not a wall of text.
- **Live CVE + supply chain in one pass.** Dependencies are checked against the OSV.dev database in real-time during every scan. No separate SCA tool needed.
- **Sovereign data routing.** Choose where your code is processed: Singapore (PDPA compliant), Jakarta (UU PDP compliant), or US. Your source code never leaves the region you select.
- **CI/CD native.** Drop it into GitHub Actions, GitLab CI, or Jenkins with one command. SARIF for GitHub Code Scanning, JUnit XML for Jenkins, GitLab Code Quality for MR widgets. Exit code 1 blocks the pipeline on critical/high findings.
- **One dependency.** The entire tool is `httpx` + Python 3.9+. No JVM, no Docker, no binary downloads.

### Side-by-Side Comparison

| Capability | Anoman CodeCheck | SonarQube / Semgrep | Manual Review |
|------------|-----------------|---------------------|---------------|
| Business logic analysis | Yes (LLM reasoning) | No | Yes |
| Credential leak detection | Yes | Partial (regex) | Yes |
| OWASP/NIST/ISO mapping | 45+ checks, auto-mapped | CWE only | Manual |
| Custom checklists | JSON export/import | YAML rules (complex) | N/A |
| CVE/dependency scanning | Built-in (OSV.dev live) | Separate tool | Usually skipped |
| Data residency control | SG / ID / US selectable | Vendor cloud only | In-house |
| Setup time | 30 seconds | Hours to days | N/A |
| False positive rate | Low (contextual reasoning) | Medium-High | Low |
| Cost | Per-scan token cost | $150-450/mo per project | $150-300/hr |
| CI/CD output formats | SARIF, JUnit, GitLab, GitHub | SARIF, JSON | None |
| Offline/air-gap mode | No (needs API) | Yes (self-hosted) | Yes |
| Deterministic results | No (LLM variance) | Yes | No |

> **When to use SAST instead:** If you need deterministic, reproducible results for audit evidence, or you're scanning 500+ files per run in a CI pipeline that runs 50x/day, traditional SAST is more cost-effective for high-frequency scans. Anoman CodeCheck is best for **deep scans** — pre-merge reviews, security audits, compliance checks, and catching what SAST misses.

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

### AI-Powered Code Analysis
- **Claude Opus reasoning** — not regex matching. The LLM reads your code, traces data flows, understands business logic, and identifies vulnerabilities that pattern-based scanners miss.
- **30+ language support** — Python, JavaScript/TypeScript, Java, Go, Rust, Ruby, PHP, C/C++, Swift, Kotlin, Scala, SQL, Shell, Terraform, Dockerfiles, YAML/JSON/TOML configs.
- **Structured findings** — every issue includes severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), exact file + line, description, fix recommendation, and mapped framework control ID.

### Compliance Checklists (45+ Checks)
- **OWASP API Security Top 10 (2023)** — Broken Object-Level Auth, Broken Authentication, Injection, SSRF, Mass Assignment, and more.
- **OWASP Web Top 10 (2021)** — Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, and more.
- **NIST SP 800-53 Rev 5** — Access Control, Audit & Accountability, System & Communications Protection, Incident Response.
- **ISO 27001:2022 Annex A** — Access Management, Cryptography, Operations Security, Communications Security.
- **Infrastructure** — Docker misconfigurations, Terraform security, secrets in IaC, exposed ports, privilege escalation.
- **Mobile (OWASP MASVS 2.0)** — Insecure data storage, weak auth, insufficient crypto, code tampering, reverse engineering.
- **Custom checklists** — Export any checklist to JSON, edit it, add your own checks, and scan with `--custom-checklist`.

### Live CVE & Supply Chain Scanning
- **OSV.dev integration** — queries the Open Source Vulnerability database on every scan. No stale advisory data.
- **Dependency file parsing** — automatically detects and parses `requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, `Gemfile.lock`.
- **CVE findings merged into report** — supply chain vulnerabilities appear alongside code findings with fix versions and advisory URLs.

### CI/CD Integration
- **SARIF 2.1.0** — GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer.
- **JUnit XML** — Jenkins, GitLab, CircleCI, any JUnit-compatible runner.
- **GitLab Code Quality** — native MR widget integration.
- **GitHub Annotations** — inline PR comments (auto-detected in GitHub Actions).
- **CI gating** — `--fail-on critical|high|medium` exits with code 1 to block the pipeline.

### Sovereign Data Routing
- **Singapore** — code processed in AWS ap-southeast-1, PDPA compliant.
- **Jakarta** — code processed in AWS ap-southeast-3, UU PDP compliant.
- **US** — standard routing, lowest latency for non-regulated workloads.
- **Your code stays in the region you choose.** No cross-border data transfer.

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
