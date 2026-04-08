"""Anoman CodeCheck — AI-powered codebase security & quality scanner.

Features:
- SAST scan using Claude Opus via Anoman AI sovereign gateway
- Pre-built checklists (OWASP, NIST, ISO 27001) mapped to codebase types
- Custom checklist support (JSON format)
- Live CVE database lookup (OSV.dev) for supply chain vulnerabilities
- CI/CD output formats: SARIF, JUnit XML, GitLab Code Quality, GitHub annotations
- Sovereign data routing: scan with data staying in Singapore or Jakarta

Usage:
    anoman-codecheck scan ./my-project
    anoman-codecheck scan ./my-project --checklist owasp-api --type api
    anoman-codecheck scan ./my-project --custom-checklist my-checks.json
    anoman-codecheck scan ./my-project --output sarif --output-file results.sarif
    anoman-codecheck checklists                    # List available checklists
    anoman-codecheck checklist owasp-api --export  # Export checklist to JSON for customization
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

from anoman_codecheck.checklists.registry import (
    get_checklist,
    get_combined_checklist,
    list_checklists,
    list_categories,
    load_custom_checklist,
    Checklist,
)
from anoman_codecheck.cve.lookup import scan_dependencies, CVEResult
from anoman_codecheck.ci.formatters import format_output

DEFAULT_GATEWAY = "https://api.anoman.io"
DEFAULT_MODEL = "claude-opus-bedrock-sg"

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".scala",
    ".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".cfg",
    ".sql", ".sh", ".bash", ".dockerfile", ".tf",
}

SKIP_PATTERNS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", ".cache", "coverage", ".pytest_cache",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}

MAX_FILE_SIZE = 100_000

# ═══════════════════════════════════════════════════════════════════════

def collect_files(root: Path, max_files: int = 50) -> list[tuple[str, str]]:
    files = []
    for path in sorted(root.rglob("*")):
        if any(skip in str(path) for skip in SKIP_PATTERNS):
            continue
        if not path.is_file() or path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if path.stat().st_size > MAX_FILE_SIZE or len(files) >= max_files:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            files.append((str(path.relative_to(root)), content))
        except Exception:
            continue
    return files


def build_scan_payload(files: list[tuple[str, str]]) -> str:
    parts = []
    for path, content in files:
        if len(content) > 5000:
            content = content[:5000] + "\n... (truncated)"
        parts.append(f"--- FILE: {path} ---\n{content}\n")
    return "\n".join(parts)


def build_prompt(checklist: Checklist | None, code_payload: str, cve_findings: list[CVEResult] | None = None) -> str:
    """Build the full LLM prompt with checklist + code + CVE context."""
    parts = ["You are a senior security engineer performing a comprehensive code review.\n"]

    if checklist:
        parts.append("Use this security checklist to guide your review:\n")
        parts.append(checklist.to_prompt())
        parts.append("\n")

    parts.append("""For each finding, provide:
- severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- category: security / credential / quality / compliance / supply_chain
- file: exact file path
- line: line number (if identifiable)
- description: what the issue is
- recommendation: how to fix it
- framework: which framework control (OWASP, NIST, ISO, CWE)
- framework_id: control ID (e.g. A01:2021, CWE-89)

Respond in JSON format:
{
  "findings": [...],
  "summary": {"total": N, "critical": N, "high": N, "medium": N, "low": N, "clean_files": N}
}
""")

    if cve_findings:
        parts.append("\nKNOWN CVEs IN DEPENDENCIES (from OSV.dev live lookup):\n")
        for cve in cve_findings:
            parts.append(f"  {cve.cve_id}: {cve.package}@{cve.version} — {cve.severity} — {cve.summary[:100]}")
            if cve.fix_version:
                parts.append(f"    Fix: upgrade to {cve.fix_version}")
            parts.append("")
        parts.append("Include these CVEs in your findings with category 'supply_chain'.\n")

    parts.append("\nCODE TO ANALYZE:\n")
    parts.append(code_payload)

    return "\n".join(parts)


def scan_with_llm(prompt: str, api_key: str, gateway: str = DEFAULT_GATEWAY, model: str = DEFAULT_MODEL) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 4096, "temperature": 0.1}

    print(f"  Sending to {gateway} via model {model}...")
    start = time.time()

    try:
        r = httpx.post(f"{gateway}/v1/chat/completions", headers=headers, json=body, timeout=300.0)
    except httpx.TimeoutException:
        return {"error": "Request timed out (300s)", "status": 0}

    elapsed = time.time() - start
    print(f"  Response: HTTP {r.status_code} in {elapsed:.1f}s")

    if r.status_code != 200:
        return {"error": r.text[:500], "status": r.status_code}

    data = r.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    usage = data.get("usage", {})
    print(f"  Tokens: {usage.get('prompt_tokens', 0)} in / {usage.get('completion_tokens', 0)} out")

    try:
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(content[json_start:json_end])
            result["_meta"] = {"model": data.get("model", model), "tokens": usage, "latency_s": round(elapsed, 1)}
            return result
    except json.JSONDecodeError:
        pass

    return {"raw_response": content, "_meta": {"model": model, "latency_s": round(elapsed, 1)}}


def print_report(result: dict[str, Any]):
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
        for sev in ["critical", "high", "medium", "low"]:
            count = summary.get(sev, 0)
            marker = "!!" if sev in ("critical", "high") and count > 0 else "  "
            print(f"  {marker}{sev.capitalize():10s}: {count}")

    if findings:
        print(f"\n  Findings ({len(findings)}):")
        print("  " + "-" * 56)
        for f in findings:
            sev = f.get("severity", "?")
            icon = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* ", "LOW": "- ", "INFO": "  "}.get(sev, "? ")
            print(f"\n  [{icon}] {sev} — {f.get('category', '?')}")
            if f.get("framework"):
                print(f"      Framework: {f.get('framework', '')} {f.get('framework_id', '')}")
            print(f"      File: {f.get('file', '?')}:{f.get('line', '?')}")
            print(f"      {f.get('description', '?')}")
            print(f"      Fix: {f.get('recommendation', '?')}")
    else:
        print("\n  No findings — code looks clean!")

    if meta:
        print(f"\n  Scan metadata:")
        print(f"    Model: {meta.get('model', '?')}")
        print(f"    Latency: {meta.get('latency_s', '?')}s")
    print("\n" + "=" * 60)


def determine_exit_code(result: dict[str, Any], fail_on: str = "high") -> int:
    """Determine CI exit code based on findings severity."""
    summary = result.get("summary", {})
    if fail_on == "critical" and summary.get("critical", 0) > 0:
        return 1
    if fail_on == "high" and (summary.get("critical", 0) + summary.get("high", 0)) > 0:
        return 1
    if fail_on == "medium" and (summary.get("critical", 0) + summary.get("high", 0) + summary.get("medium", 0)) > 0:
        return 1
    return 0


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Anoman CodeCheck — AI-powered codebase security & quality scanner",
        epilog="Powered by Anoman AI (https://anoman.io)",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── scan command ──
    scan_parser = subparsers.add_parser("scan", help="Scan a codebase for security issues")
    scan_parser.add_argument("path", help="Path to the codebase")
    scan_parser.add_argument("--api-key", default=os.environ.get("ANOMAN_API_KEY"))
    scan_parser.add_argument("--gateway", default=os.environ.get("ANOMAN_GATEWAY", DEFAULT_GATEWAY))
    scan_parser.add_argument("--model", default=DEFAULT_MODEL)
    scan_parser.add_argument("--type", choices=["api", "backend", "frontend", "mobile", "infra"], help="Codebase type (auto-selects checklists)")
    scan_parser.add_argument("--checklist", help="Use a specific checklist (e.g. owasp-api, nist, iso27001, infra, mobile)")
    scan_parser.add_argument("--custom-checklist", help="Path to custom checklist JSON file")
    scan_parser.add_argument("--no-checklist", action="store_true", help="Disable checklist (free-form AI scan)")
    scan_parser.add_argument("--no-cve", action="store_true", help="Skip CVE/dependency scanning")
    scan_parser.add_argument("--max-files", type=int, default=50)
    scan_parser.add_argument("--output", choices=["text", "json", "sarif", "junit", "gitlab", "github"], default="text")
    scan_parser.add_argument("--output-file", help="Save results to file")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "none"], default="high", help="Exit code 1 if findings at this severity or above (default: high)")

    # ── checklists command ──
    cl_parser = subparsers.add_parser("checklists", help="List available security checklists")

    # ── checklist command ──
    detail_parser = subparsers.add_parser("checklist", help="View or export a specific checklist")
    detail_parser.add_argument("name", help="Checklist name (e.g. owasp-api)")
    detail_parser.add_argument("--export", action="store_true", help="Export as JSON for customization")
    detail_parser.add_argument("--export-file", help="Export to file")

    args = parser.parse_args()

    if args.command == "checklists":
        print("\nAvailable checklists:")
        for key, name in list_checklists().items():
            print(f"  {key:15s} — {name}")
        print("\nCodebase type → auto-selected checklists:")
        for ctype, cls in list_categories().items():
            print(f"  {ctype:12s} → {', '.join(cls)}")
        print("\nUsage: anoman-codecheck scan ./path --checklist owasp-api")
        print("       anoman-codecheck checklist owasp-api --export")
        return

    if args.command == "checklist":
        cl = get_checklist(args.name)
        if not cl:
            print(f"Checklist '{args.name}' not found. Use 'anoman-codecheck checklists' to see available.")
            sys.exit(1)
        if args.export or args.export_file:
            output = cl.to_json()
            if args.export_file:
                Path(args.export_file).write_text(output)
                print(f"Exported to {args.export_file}")
            else:
                print(output)
        else:
            print(f"\n{cl.name} (v{cl.version})")
            print(f"{cl.description}\n")
            for item in cl.items:
                status = "ON " if item.enabled else "OFF"
                print(f"  [{status}] [{item.severity:8s}] {item.id}: {item.title}")
                print(f"         {item.framework} {item.framework_id} | Types: {', '.join(item.codebase_types)}")
                print(f"         {item.check_prompt[:80]}...")
                print()
        return

    if args.command != "scan":
        parser.print_help()
        return

    if not args.api_key:
        print("Error: API key required. Set ANOMAN_API_KEY or use --api-key.")
        sys.exit(1)

    project_path = Path(args.path).resolve()
    if not project_path.exists():
        print(f"Error: Path not found: {project_path}")
        sys.exit(1)

    print(f"\nAnoman CodeCheck v0.1.0")
    print(f"  Scanning: {project_path}")
    print(f"  Model: {args.model}")
    print(f"  Gateway: {args.gateway}")

    # ── Resolve checklist ──
    checklist: Checklist | None = None
    if args.no_checklist:
        print(f"  Checklist: disabled (free-form AI scan)")
    elif args.custom_checklist:
        checklist = load_custom_checklist(args.custom_checklist)
        print(f"  Checklist: custom — {checklist.name} ({len(checklist.items)} items)")
    elif args.checklist:
        checklist = get_checklist(args.checklist)
        if not checklist:
            print(f"  Warning: checklist '{args.checklist}' not found, using free-form scan")
        else:
            print(f"  Checklist: {checklist.name} ({len(checklist.items)} items)")
    elif args.type:
        checklist = get_combined_checklist(args.type)
        print(f"  Checklist: auto ({args.type}) — {len(checklist.items)} items from {len(list_categories().get(args.type, []))} frameworks")
    else:
        print(f"  Checklist: default (owasp-web + nist)")
        from anoman_codecheck.checklists.registry import OWASP_WEB_CHECKLIST, NIST_CHECKLIST
        checklist = Checklist(name="Default", description="OWASP + NIST", version="1.0",
            items=OWASP_WEB_CHECKLIST.items + NIST_CHECKLIST.items)

    # ── CVE scan ──
    cve_findings: list[CVEResult] = []
    if not args.no_cve:
        print(f"\n  Scanning dependencies for known CVEs (OSV.dev)...")
        cve_findings = scan_dependencies(project_path)
        if cve_findings:
            print(f"  Found {len(cve_findings)} known CVEs in dependencies:")
            for cve in cve_findings[:5]:
                print(f"    {cve.cve_id}: {cve.package}@{cve.version} [{cve.severity}]")
            if len(cve_findings) > 5:
                print(f"    ... and {len(cve_findings) - 5} more")
        else:
            print(f"  No known CVEs found in dependencies")

    # ── Collect files ──
    print(f"\n  Collecting source files...")
    files = collect_files(project_path, max_files=args.max_files)
    print(f"  Found {len(files)} scannable files")

    if not files:
        print("  No scannable files found.")
        sys.exit(1)

    # ── Build payload + scan ──
    payload = build_scan_payload(files)
    print(f"  Payload size: {len(payload):,} chars")

    prompt = build_prompt(checklist, payload, cve_findings if cve_findings else None)
    print(f"\n  Running AI security scan...")

    result = scan_with_llm(prompt, args.api_key, args.gateway, args.model)

    # Merge CVE findings into results
    if cve_findings and "findings" in result:
        for cve in cve_findings:
            result["findings"].append({
                "severity": cve.severity,
                "category": "supply_chain",
                "file": "dependencies",
                "line": "",
                "description": f"{cve.cve_id}: {cve.package}@{cve.version} — {cve.summary[:150]}",
                "recommendation": f"Upgrade to {cve.fix_version}" if cve.fix_version else "Check vendor advisory",
                "framework": "CWE",
                "framework_id": "CWE-1035",
                "url": cve.url,
            })
        # Update summary
        if "summary" in result:
            result["summary"]["total"] = len(result["findings"])

    # ── Output ──
    if args.output == "text":
        print_report(result)
    else:
        formatted = format_output(result, args.output)
        if args.output_file:
            Path(args.output_file).write_text(formatted)
            print(f"\n  Results saved to {args.output_file} ({args.output} format)")
        else:
            print(formatted)

    # ── GitHub annotations (always print if in GitHub Actions) ──
    if os.environ.get("GITHUB_ACTIONS") and result.get("findings"):
        from anoman_codecheck.ci.formatters import to_github_annotations
        for annotation in to_github_annotations(result):
            print(annotation)

    # ── Exit code for CI ──
    if args.fail_on != "none":
        exit_code = determine_exit_code(result, args.fail_on)
        if exit_code != 0:
            print(f"\n  CI gate: FAILED (findings at {args.fail_on} severity or above)")
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
