"""CI/CD output formatters — SARIF, JUnit XML, GitLab Code Quality, GitHub annotations.

Each formatter takes scan results and outputs in a format that CI/CD runners
can natively understand for reporting, gating, and annotations.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any


def to_sarif(results: dict[str, Any], tool_name: str = "anoman-codecheck", version: str = "0.1.0") -> dict[str, Any]:
    """Convert scan results to SARIF 2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) is supported by:
    GitHub Code Scanning, Azure DevOps, VS Code, many CI tools.
    """
    findings = results.get("findings", [])

    rules = []
    sarif_results = []

    for i, f in enumerate(findings):
        rule_id = f.get("id", f"finding-{i}")
        severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
        level = severity_map.get(f.get("severity", "MEDIUM"), "warning")

        rules.append({
            "id": rule_id,
            "name": f.get("category", "security"),
            "shortDescription": {"text": f.get("description", "")[:200]},
            "helpUri": f.get("url", "https://anoman.io/docs"),
            "properties": {
                "severity": f.get("severity", "MEDIUM"),
                "category": f.get("category", "security"),
                "framework": f.get("framework", ""),
                "framework_id": f.get("framework_id", ""),
            },
        })

        location = {}
        if f.get("file"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": int(f.get("line", 1))} if f.get("line") else {},
                }
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("description", "") + "\n\nRecommendation: " + f.get("recommendation", "")},
            "locations": [location] if location else [],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": version,
                    "informationUri": "https://github.com/c0denician88/anoman-codecheck",
                    "rules": rules,
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }


def to_junit_xml(results: dict[str, Any], suite_name: str = "anoman-codecheck") -> str:
    """Convert scan results to JUnit XML format.

    JUnit XML is supported by: Jenkins, GitLab CI, CircleCI, GitHub Actions.
    Findings are reported as test failures — CI can gate on them.
    """
    findings = results.get("findings", [])
    summary = results.get("summary", {})

    testsuite = ET.Element("testsuite", {
        "name": suite_name,
        "tests": str(summary.get("total", len(findings))),
        "failures": str(summary.get("critical", 0) + summary.get("high", 0)),
        "errors": "0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    for f in findings:
        testcase = ET.SubElement(testsuite, "testcase", {
            "name": f.get("description", "finding")[:200],
            "classname": f.get("file", "unknown"),
            "time": "0",
        })

        if f.get("severity") in ("CRITICAL", "HIGH"):
            failure = ET.SubElement(testcase, "failure", {
                "message": f.get("description", ""),
                "type": f.get("category", "security"),
            })
            failure.text = f"Severity: {f.get('severity')}\nFile: {f.get('file', '?')}:{f.get('line', '?')}\nRecommendation: {f.get('recommendation', '')}"
        elif f.get("severity") in ("MEDIUM", "LOW"):
            ET.SubElement(testcase, "system-out").text = f"[{f.get('severity')}] {f.get('description', '')}\nFix: {f.get('recommendation', '')}"

    # Add a passing test for clean summary
    clean = summary.get("clean_files", 0)
    if clean > 0:
        ET.SubElement(testsuite, "testcase", {"name": f"{clean} files passed security scan", "classname": "clean", "time": "0"})

    return ET.tostring(testsuite, encoding="unicode", xml_declaration=True)


def to_gitlab_codequality(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert scan results to GitLab Code Quality report format.

    GitLab CI natively renders Code Quality reports in merge request widgets.
    """
    findings = results.get("findings", [])
    severity_map = {"CRITICAL": "blocker", "HIGH": "critical", "MEDIUM": "major", "LOW": "minor", "INFO": "info"}
    category_map = {"security": "Security", "credential": "Security", "quality": "Bug Risk", "compliance": "Security"}

    report = []
    for f in findings:
        import hashlib
        fingerprint = hashlib.md5(json.dumps(f, sort_keys=True).encode()).hexdigest()

        report.append({
            "type": "issue",
            "check_name": f.get("id", f.get("category", "security")),
            "description": f.get("description", ""),
            "content": {"body": f"Recommendation: {f.get('recommendation', '')}\nFramework: {f.get('framework', '')} {f.get('framework_id', '')}"},
            "categories": [category_map.get(f.get("category", ""), "Security")],
            "severity": severity_map.get(f.get("severity", "MEDIUM"), "major"),
            "location": {
                "path": f.get("file", "unknown"),
                "lines": {"begin": int(f.get("line", 1))} if f.get("line") else {"begin": 1},
            },
            "fingerprint": fingerprint,
        })

    return report


def to_github_annotations(results: dict[str, Any]) -> list[str]:
    """Convert scan results to GitHub Actions annotation commands.

    These are printed to stdout and GitHub Actions renders them inline on PRs.
    """
    findings = results.get("findings", [])
    severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "notice", "INFO": "notice"}
    annotations = []

    for f in findings:
        level = severity_map.get(f.get("severity", "MEDIUM"), "warning")
        file_path = f.get("file", "")
        line = f.get("line", "1")
        title = f"[{f.get('severity')}] {f.get('category', 'security')}"
        msg = f.get("description", "") + " | Fix: " + f.get("recommendation", "")
        annotations.append(f"::{level} file={file_path},line={line},title={title}::{msg}")

    return annotations


def format_output(results: dict[str, Any], fmt: str) -> str:
    """Format results in the requested CI/CD format."""
    if fmt == "sarif":
        return json.dumps(to_sarif(results), indent=2)
    elif fmt == "junit":
        return to_junit_xml(results)
    elif fmt == "gitlab":
        return json.dumps(to_gitlab_codequality(results), indent=2)
    elif fmt == "github":
        return "\n".join(to_github_annotations(results))
    elif fmt == "json":
        return json.dumps(results, indent=2)
    else:
        return json.dumps(results, indent=2)
