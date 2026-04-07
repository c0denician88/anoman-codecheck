"""Anoman CodeCheck — AI-powered codebase security & quality scanner.

Uses Claude Opus via Anoman AI gateway with sovereign routing to scan
codebases for: security vulnerabilities, credential leaks, code quality
issues, OWASP Top 10, and compliance concerns.

Usage:
    python -m anoman_codecheck scan ./my-project --region sg_only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    print("Error: httpx is required. Install with: pip install httpx")
    sys.exit(1)

DEFAULT_GATEWAY = "https://api.anoman.io"
DEFAULT_MODEL = "claude-opus-bedrock-sg"  # Sovereign SG by default

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".scala",
    ".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".cfg",
    ".sql", ".sh", ".bash", ".dockerfile", ".tf",
}

# Files to always skip
SKIP_PATTERNS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", ".cache", "coverage", ".pytest_cache",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}

# Max file size to scan (100KB)
MAX_FILE_SIZE = 100_000

SCAN_PROMPT = """You are a senior security engineer performing a comprehensive code review.
Analyze the following code for:

1. **SECURITY VULNERABILITIES** (Critical)
   - SQL injection, XSS, command injection, path traversal
   - OWASP Top 10 issues
   - Authentication/authorization flaws
   - Insecure deserialization
   - SSRF, CSRF vulnerabilities

2. **CREDENTIAL LEAKS** (Critical)
   - Hardcoded API keys, passwords, tokens, secrets
   - .env files with real values committed
   - Private keys, certificates
   - Database connection strings with credentials

3. **CODE QUALITY** (Medium)
   - Unhandled errors/exceptions
   - Race conditions
   - Memory leaks
   - Dead code
   - Anti-patterns

4. **COMPLIANCE** (Low-Medium)
   - PII handling without encryption
   - Logging of sensitive data
   - Missing audit trails
   - Data residency concerns

For each finding, provide:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category**: security / credential / quality / compliance
- **File**: exact file path
- **Line** (if identifiable): line number or range
- **Description**: what the issue is
- **Recommendation**: how to fix it

Respond in JSON format:
{
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "credential",
      "file": "config.py",
      "line": "42",
      "description": "Hardcoded database password",
      "recommendation": "Move to environment variable or secret manager"
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "clean_files": 10
  }
}

CODE TO ANALYZE:
"""


def collect_files(root: Path, max_files: int = 50) -> list[tuple[str, str]]:
    """Collect source files from the project directory."""
    files = []
    for path in sorted(root.rglob("*")):
        if any(skip in str(path) for skip in SKIP_PATTERNS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if path.stat().st_size > MAX_FILE_SIZE:
            continue
        if len(files) >= max_files:
            break
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            rel_path = str(path.relative_to(root))
            files.append((rel_path, content))
        except Exception:
            continue
    return files


def build_scan_payload(files: list[tuple[str, str]]) -> str:
    """Build the code payload for the LLM scan."""
    parts = []
    for path, content in files:
        # Truncate very long files
        if len(content) > 5000:
            content = content[:5000] + "\n... (truncated)"
        parts.append(f"--- FILE: {path} ---\n{content}\n")
    return "\n".join(parts)


def scan_with_llm(
    code_payload: str,
    api_key: str,
    gateway: str = DEFAULT_GATEWAY,
    model: str = DEFAULT_MODEL,
    region: str | None = None,
) -> dict[str, Any]:
    """Send code to the LLM for analysis via Anoman gateway."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    messages = [
        {"role": "user", "content": SCAN_PROMPT + code_payload}
    ]

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": 4096,
        "temperature": 0.1,  # Low temperature for consistent analysis
    }

    print(f"  Sending to {gateway} via model {model}...")
    start = time.time()

    r = httpx.post(
        f"{gateway}/v1/chat/completions",
        headers=headers,
        json=body,
        timeout=300.0,  # 5 min timeout for large codebases
    )

    elapsed = time.time() - start
    print(f"  Response: HTTP {r.status_code} in {elapsed:.1f}s")

    if r.status_code != 200:
        print(f"  Error: {r.text[:500]}")
        return {"error": r.text[:500], "status": r.status_code}

    data = r.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    usage = data.get("usage", {})

    print(f"  Tokens: {usage.get('prompt_tokens', 0)} in / {usage.get('completion_tokens', 0)} out")

    # Parse JSON from response
    try:
        # Find JSON in the response (may be wrapped in markdown code blocks)
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(content[json_start:json_end])
            result["_meta"] = {
                "model": data.get("model", model),
                "tokens": usage,
                "latency_s": round(elapsed, 1),
            }
            return result
    except json.JSONDecodeError:
        pass

    return {"raw_response": content, "_meta": {"model": model, "latency_s": round(elapsed, 1)}}


def print_report(result: dict[str, Any]):
    """Print a formatted security scan report."""
    print("\n" + "=" * 60)
    print("  ANOMAN CODECHECK — Security Scan Report")
    print("=" * 60)

    if "error" in result:
        print(f"\n  ERROR: {result['error']}")
        return

    findings = result.get("findings", [])
    summary = result.get("summary", {})
    meta = result.get("_meta", {})

    if summary:
        print(f"\n  Summary:")
        print(f"    Total findings: {summary.get('total', len(findings))}")
        print(f"    Critical: {summary.get('critical', 0)}")
        print(f"    High:     {summary.get('high', 0)}")
        print(f"    Medium:   {summary.get('medium', 0)}")
        print(f"    Low:      {summary.get('low', 0)}")
        if summary.get("clean_files"):
            print(f"    Clean files: {summary['clean_files']}")

    if findings:
        print(f"\n  Findings ({len(findings)}):")
        print("  " + "-" * 56)
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "?")
            sev_color = {"CRITICAL": "!", "HIGH": "!", "MEDIUM": "*", "LOW": "-", "INFO": " "}.get(sev, "?")
            print(f"\n  [{sev_color}] {sev} — {f.get('category', '?')}")
            print(f"      File: {f.get('file', '?')}:{f.get('line', '?')}")
            print(f"      {f.get('description', '?')}")
            print(f"      Fix: {f.get('recommendation', '?')}")
    else:
        print("\n  No findings — code looks clean!")

    if meta:
        print(f"\n  Scan metadata:")
        print(f"    Model: {meta.get('model', '?')}")
        print(f"    Latency: {meta.get('latency_s', '?')}s")
        tokens = meta.get("tokens", {})
        if tokens:
            print(f"    Tokens: {tokens.get('prompt_tokens', 0)} in / {tokens.get('completion_tokens', 0)} out")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Anoman CodeCheck — AI-powered codebase security & quality scanner",
        epilog="Powered by Anoman AI (https://anoman.io) — secure every AI call.",
    )
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("path", help="Path to the codebase to scan")
    parser.add_argument("--api-key", default=os.environ.get("ANOMAN_API_KEY"), help="Anoman API key (or set ANOMAN_API_KEY env var)")
    parser.add_argument("--gateway", default=os.environ.get("ANOMAN_GATEWAY", DEFAULT_GATEWAY), help="Anoman gateway URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model to use (default: {DEFAULT_MODEL})")
    parser.add_argument("--region", choices=["any", "sg_only", "id_only"], default=None, help="Data residency preference")
    parser.add_argument("--max-files", type=int, default=50, help="Maximum files to scan (default: 50)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output-file", help="Save results to file")

    args = parser.parse_args()

    if not args.api_key:
        print("Error: API key required. Set ANOMAN_API_KEY env var or use --api-key flag.")
        print("  Get one free at https://app.anoman.io")
        sys.exit(1)

    project_path = Path(args.path).resolve()
    if not project_path.exists():
        print(f"Error: Path not found: {project_path}")
        sys.exit(1)

    print(f"\nAnoman CodeCheck v0.1.0")
    print(f"  Scanning: {project_path}")
    print(f"  Model: {args.model}")
    print(f"  Gateway: {args.gateway}")
    if args.region:
        print(f"  Region: {args.region}")

    # Collect files
    print(f"\n  Collecting files...")
    files = collect_files(project_path, max_files=args.max_files)
    print(f"  Found {len(files)} scannable files")

    if not files:
        print("  No scannable files found. Check the path and file extensions.")
        sys.exit(1)

    # Build payload
    payload = build_scan_payload(files)
    print(f"  Payload size: {len(payload):,} chars")

    # Scan
    print(f"\n  Running AI security scan...")
    result = scan_with_llm(
        code_payload=payload,
        api_key=args.api_key,
        gateway=args.gateway,
        model=args.model,
        region=args.region,
    )

    # Output
    if args.output == "json":
        output = json.dumps(result, indent=2)
        if args.output_file:
            Path(args.output_file).write_text(output)
            print(f"\n  Results saved to {args.output_file}")
        else:
            print(output)
    else:
        print_report(result)
        if args.output_file:
            # Save JSON alongside text output
            Path(args.output_file).write_text(json.dumps(result, indent=2))
            print(f"\n  JSON results saved to {args.output_file}")


if __name__ == "__main__":
    main()
