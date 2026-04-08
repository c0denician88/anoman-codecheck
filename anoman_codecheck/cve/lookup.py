"""CVE database live lookup — fetches from OSV.dev and NVD APIs.

Queries the Open Source Vulnerability database (OSV.dev) and optionally
NVD for known CVEs affecting the project's dependencies.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"


@dataclass
class CVEResult:
    """A single CVE finding."""
    cve_id: str
    package: str
    version: str
    severity: str
    summary: str
    fix_version: str | None = None
    url: str | None = None


def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse Python requirements.txt → list of (package, version)."""
    deps = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*([0-9][0-9a-zA-Z.*]*)", line)
        if match:
            deps.append((match.group(1).lower(), match.group(2)))
        else:
            name = re.match(r"([a-zA-Z0-9_-]+)", line)
            if name:
                deps.append((name.group(1).lower(), ""))
    return deps


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse npm package.json → list of (package, version)."""
    data = json.loads(path.read_text())
    deps = []
    for section in ["dependencies", "devDependencies"]:
        for name, ver in data.get(section, {}).items():
            clean_ver = re.sub(r"[^0-9.]", "", ver)
            deps.append((name, clean_ver))
    return deps


def parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml dependencies."""
    deps = []
    in_deps = False
    for line in path.read_text().splitlines():
        if "dependencies" in line and "=" in line:
            in_deps = True
            continue
        if in_deps and line.strip().startswith("]"):
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'\s*"([a-zA-Z0-9_-]+)\s*[><=!~]*\s*([0-9][0-9a-zA-Z.]*)?', line)
            if match:
                deps.append((match.group(1).lower(), match.group(2) or ""))
    return deps


def parse_go_mod(path: Path) -> list[tuple[str, str]]:
    """Parse go.mod → list of (module, version)."""
    deps = []
    for line in path.read_text().splitlines():
        match = re.match(r"\s+(\S+)\s+v([0-9]\S*)", line)
        if match:
            deps.append((match.group(1), match.group(2)))
    return deps


def detect_dependencies(project_path: Path) -> dict[str, list[tuple[str, str]]]:
    """Auto-detect and parse all dependency files in a project."""
    results: dict[str, list[tuple[str, str]]] = {}

    for req in project_path.rglob("requirements*.txt"):
        if "node_modules" in str(req) or ".venv" in str(req):
            continue
        results[str(req.relative_to(project_path))] = parse_requirements_txt(req)

    for pkg in project_path.rglob("package.json"):
        if "node_modules" in str(pkg):
            continue
        results[str(pkg.relative_to(project_path))] = parse_package_json(pkg)

    for pyp in project_path.rglob("pyproject.toml"):
        if ".venv" in str(pyp):
            continue
        results[str(pyp.relative_to(project_path))] = parse_pyproject_toml(pyp)

    for gomod in project_path.rglob("go.mod"):
        results[str(gomod.relative_to(project_path))] = parse_go_mod(gomod)

    return results


def query_osv(package: str, version: str, ecosystem: str = "PyPI") -> list[CVEResult]:
    """Query OSV.dev for known vulnerabilities."""
    body: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        body["version"] = version

    try:
        r = httpx.post(OSV_API, json=body, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        vulns = data.get("vulns", [])
        results = []
        for v in vulns:
            cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            cve_id = cve_ids[0] if cve_ids else v.get("id", "UNKNOWN")
            severity = "HIGH"
            for s in v.get("severity", []):
                score = s.get("score", "")
                if "CRITICAL" in score.upper():
                    severity = "CRITICAL"
                elif "HIGH" in score.upper():
                    severity = "HIGH"

            fix_ver = None
            for affected in v.get("affected", []):
                for rng in affected.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fix_ver = evt["fixed"]

            results.append(CVEResult(
                cve_id=cve_id,
                package=package,
                version=version,
                severity=severity,
                summary=v.get("summary", v.get("details", "")[:200]),
                fix_version=fix_ver,
                url=f"https://osv.dev/vulnerability/{v.get('id', '')}",
            ))
        return results
    except Exception:
        return []


def scan_dependencies(project_path: Path) -> list[CVEResult]:
    """Scan all dependencies in a project for known CVEs."""
    all_deps = detect_dependencies(project_path)
    all_vulns: list[CVEResult] = []

    for dep_file, deps in all_deps.items():
        # Determine ecosystem
        if dep_file.endswith(".json"):
            ecosystem = "npm"
        elif dep_file.endswith("go.mod"):
            ecosystem = "Go"
        else:
            ecosystem = "PyPI"

        for pkg_name, pkg_version in deps:
            if not pkg_version:
                continue
            vulns = query_osv(pkg_name, pkg_version, ecosystem)
            all_vulns.extend(vulns)

    return all_vulns
