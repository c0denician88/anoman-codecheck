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
