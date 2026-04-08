"""Checklist registry — pre-built security checklists mapped to OWASP, NIST, ISO.

Each checklist item maps to a framework control ID and is categorized by
codebase type (api, frontend, backend, mobile, infra).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ChecklistItem:
    """A single security check item."""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    category: str  # injection / auth / crypto / config / supply_chain / pii / access
    framework: str  # OWASP / NIST / ISO / CWE
    framework_id: str  # e.g. A01:2021, SP800-53 AC-2, ISO27001 A.9
    codebase_types: list[str]  # api, frontend, backend, mobile, infra
    check_prompt: str  # What to look for in the code
    enabled: bool = True


@dataclass
class Checklist:
    """A collection of checklist items."""
    name: str
    description: str
    version: str
    items: list[ChecklistItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_prompt(self) -> str:
        """Convert enabled items to an LLM-readable checklist prompt."""
        lines = [f"SECURITY CHECKLIST: {self.name}\n"]
        for item in self.items:
            if not item.enabled:
                continue
            lines.append(
                f"[{item.id}] [{item.severity}] {item.title}\n"
                f"  Framework: {item.framework} {item.framework_id}\n"
                f"  Check: {item.check_prompt}\n"
            )
        return "\n".join(lines)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Checklist:
        items = [ChecklistItem(**i) for i in data.get("items", [])]
        return cls(name=data["name"], description=data["description"], version=data.get("version", "1.0"), items=items)


# ═══════════════════════════════════════════════════════════════════════
# Pre-built checklists
# ═══════════════════════════════════════════════════════════════════════

OWASP_API_CHECKLIST = Checklist(
    name="OWASP API Security Top 10 (2023)",
    description="API-specific security checks based on OWASP API Security Top 10",
    version="2023.1",
    items=[
        ChecklistItem("API01", "Broken Object Level Authorization", "Check if API endpoints expose object IDs without proper authorization checks", "CRITICAL", "auth", "OWASP", "API1:2023", ["api", "backend"], "Look for endpoints that take object IDs (user_id, order_id) in URL params or body without verifying the requesting user owns that object"),
        ChecklistItem("API02", "Broken Authentication", "Check for weak auth mechanisms, missing token validation, credential stuffing vulnerabilities", "CRITICAL", "auth", "OWASP", "API2:2023", ["api", "backend"], "Look for: missing rate limiting on login, JWT without expiry, tokens in URL params, missing token validation, hardcoded credentials"),
        ChecklistItem("API03", "Broken Object Property Level Authorization", "Check if API returns more data than the client needs", "HIGH", "auth", "OWASP", "API3:2023", ["api", "backend"], "Look for: API responses returning internal fields (password_hash, admin flags, internal IDs), mass assignment vulnerabilities, missing response filtering"),
        ChecklistItem("API04", "Unrestricted Resource Consumption", "Check for missing rate limiting and resource quotas", "HIGH", "config", "OWASP", "API4:2023", ["api", "backend"], "Look for: missing rate limiting, no pagination limits, unbounded file uploads, no timeout on external calls, missing max_tokens on LLM calls"),
        ChecklistItem("API05", "Broken Function Level Authorization", "Check if admin functions are accessible to regular users", "CRITICAL", "auth", "OWASP", "API5:2023", ["api", "backend"], "Look for: admin endpoints without role checks, missing RBAC enforcement, privilege escalation paths, missing middleware on sensitive routes"),
        ChecklistItem("API06", "Unrestricted Access to Sensitive Business Flows", "Check if critical business flows lack protection", "MEDIUM", "access", "OWASP", "API6:2023", ["api", "backend"], "Look for: payment flows without idempotency, missing CSRF protection, no re-authentication for sensitive actions"),
        ChecklistItem("API07", "Server Side Request Forgery (SSRF)", "Check for SSRF vulnerabilities in URL parameters", "HIGH", "injection", "OWASP", "API7:2023", ["api", "backend"], "Look for: user-supplied URLs used in server-side fetch/requests, webhook URLs without validation, file import from URLs without allowlist"),
        ChecklistItem("API08", "Security Misconfiguration", "Check for insecure defaults and missing security headers", "MEDIUM", "config", "OWASP", "API8:2023", ["api", "backend", "infra"], "Look for: CORS wildcard (*), missing security headers (HSTS, X-Frame), debug mode enabled, verbose error messages exposing internals, default credentials"),
        ChecklistItem("API09", "Improper Inventory Management", "Check for exposed debug/test endpoints in production", "MEDIUM", "config", "OWASP", "API9:2023", ["api", "backend"], "Look for: /debug, /test, /admin endpoints without auth, swagger/docs exposed in production without auth, deprecated API versions still active"),
        ChecklistItem("API10", "Unsafe Consumption of APIs", "Check if third-party API responses are trusted blindly", "MEDIUM", "injection", "OWASP", "API10:2023", ["api", "backend"], "Look for: third-party API responses used without validation, missing input sanitization on webhook payloads, trusting upstream data without schema validation"),
    ],
)

OWASP_WEB_CHECKLIST = Checklist(
    name="OWASP Web Application Top 10 (2021)",
    description="Web application security checks based on OWASP Top 10",
    version="2021.1",
    items=[
        ChecklistItem("WEB01", "Injection", "Check for SQL, NoSQL, OS, LDAP injection vulnerabilities", "CRITICAL", "injection", "OWASP", "A03:2021", ["backend", "api"], "Look for: string concatenation in SQL queries, unsanitized user input in shell commands, template injection, LDAP injection"),
        ChecklistItem("WEB02", "Cryptographic Failures", "Check for weak cryptography, plaintext secrets, missing encryption", "HIGH", "crypto", "OWASP", "A02:2021", ["backend", "api", "frontend"], "Look for: MD5/SHA1 for passwords (use bcrypt), plaintext passwords in DB, missing HTTPS enforcement, weak TLS versions, hardcoded encryption keys"),
        ChecklistItem("WEB03", "Cross-Site Scripting (XSS)", "Check for reflected, stored, and DOM-based XSS", "HIGH", "injection", "OWASP", "A03:2021", ["frontend", "backend"], "Look for: dangerouslySetInnerHTML without sanitization, innerHTML assignments, unescaped template variables, missing Content-Security-Policy"),
        ChecklistItem("WEB04", "Insecure Design", "Check for missing threat modeling and security controls", "MEDIUM", "access", "OWASP", "A04:2021", ["backend", "api", "frontend"], "Look for: missing rate limiting on sensitive operations, no account lockout after failed attempts, predictable resource IDs, missing re-authentication"),
        ChecklistItem("WEB05", "Security Misconfiguration", "Check for default configs, unnecessary features, verbose errors", "MEDIUM", "config", "OWASP", "A05:2021", ["backend", "api", "infra", "frontend"], "Look for: debug=True in production, default admin credentials, unnecessary HTTP methods enabled, directory listing, stack traces in error responses"),
        ChecklistItem("WEB06", "Vulnerable Components", "Check for known vulnerabilities in dependencies", "HIGH", "supply_chain", "OWASP", "A06:2021", ["backend", "api", "frontend", "mobile"], "Look for: outdated packages with known CVEs, unmaintained dependencies, packages with critical security advisories"),
        ChecklistItem("WEB07", "Authentication Failures", "Check for credential stuffing, brute force, session management issues", "CRITICAL", "auth", "OWASP", "A07:2021", ["backend", "api"], "Look for: no rate limiting on login, session tokens in URL, missing session expiry, weak password requirements, missing MFA support"),
        ChecklistItem("WEB08", "Data Integrity Failures", "Check for insecure deserialization and CI/CD pipeline integrity", "HIGH", "injection", "OWASP", "A08:2021", ["backend", "api", "infra"], "Look for: pickle.loads on untrusted data, yaml.load without SafeLoader, unsigned packages, CI/CD without pinned versions"),
        ChecklistItem("WEB09", "Logging & Monitoring Failures", "Check for insufficient logging and missing security monitoring", "MEDIUM", "config", "OWASP", "A09:2021", ["backend", "api"], "Look for: missing audit logs for auth events, PII in logs, no alerting on suspicious activity, missing request tracing"),
        ChecklistItem("WEB10", "SSRF", "Check for Server-Side Request Forgery", "HIGH", "injection", "OWASP", "A10:2021", ["backend", "api"], "Look for: user-controlled URLs in fetch/requests, internal network accessible via SSRF, cloud metadata endpoint accessible"),
    ],
)

NIST_CHECKLIST = Checklist(
    name="NIST SP 800-53 Security Controls (Selected)",
    description="Key security controls from NIST Special Publication 800-53",
    version="rev5",
    items=[
        ChecklistItem("NIST01", "Access Control (AC-2)", "Check for proper account management and access controls", "HIGH", "auth", "NIST", "AC-2", ["api", "backend"], "Look for: missing role-based access control, accounts without expiration, shared credentials, missing principle of least privilege"),
        ChecklistItem("NIST02", "Audit and Accountability (AU-2)", "Check for audit logging of security-relevant events", "MEDIUM", "config", "NIST", "AU-2", ["api", "backend"], "Look for: missing logging of login attempts, privilege changes, data access, admin actions. Check if logs include who, what, when, where"),
        ChecklistItem("NIST03", "Security Assessment (CA-2)", "Check for security testing and vulnerability scanning", "MEDIUM", "config", "NIST", "CA-2", ["infra"], "Look for: missing CI/CD security scanning, no dependency audit, no SAST/DAST in pipeline, missing penetration test evidence"),
        ChecklistItem("NIST04", "Configuration Management (CM-6)", "Check for secure configuration baselines", "MEDIUM", "config", "NIST", "CM-6", ["infra", "backend"], "Look for: default passwords, unnecessary services enabled, debug mode in production, overly permissive firewall rules, root access enabled"),
        ChecklistItem("NIST05", "Identification and Authentication (IA-2)", "Check for strong authentication mechanisms", "HIGH", "auth", "NIST", "IA-2", ["api", "backend"], "Look for: passwords stored in plaintext, missing MFA, weak password policies, missing brute force protection, session fixation"),
        ChecklistItem("NIST06", "System and Communications Protection (SC-8)", "Check for data-in-transit protection", "HIGH", "crypto", "NIST", "SC-8", ["api", "backend", "infra"], "Look for: HTTP without TLS, self-signed certificates in production, weak cipher suites, missing certificate validation"),
        ChecklistItem("NIST07", "System and Information Integrity (SI-2)", "Check for vulnerability remediation processes", "HIGH", "supply_chain", "NIST", "SI-2", ["infra", "backend"], "Look for: unpatched systems, outdated base images, known CVEs in dependencies, missing automated update process"),
    ],
)

ISO27001_CHECKLIST = Checklist(
    name="ISO 27001:2022 Annex A Controls (Selected)",
    description="Information security controls from ISO/IEC 27001:2022",
    version="2022",
    items=[
        ChecklistItem("ISO01", "Access Control Policy (A.5.15)", "Check for documented and enforced access control", "HIGH", "auth", "ISO", "A.5.15", ["api", "backend"], "Look for: missing RBAC implementation, no access control documentation, shared admin accounts, missing access reviews"),
        ChecklistItem("ISO02", "Cryptography (A.8.24)", "Check for proper use of cryptographic controls", "HIGH", "crypto", "ISO", "A.8.24", ["backend", "api"], "Look for: weak hashing algorithms, missing encryption at rest, hardcoded keys, insufficient key length, missing key rotation"),
        ChecklistItem("ISO03", "Secure Development (A.8.25)", "Check for secure coding practices", "MEDIUM", "config", "ISO", "A.8.25", ["backend", "api", "frontend"], "Look for: missing input validation, no output encoding, SQL injection, XSS, missing security headers, no CSP"),
        ChecklistItem("ISO04", "Information Security in Supplier Relationships (A.5.19)", "Check for supply chain security", "MEDIUM", "supply_chain", "ISO", "A.5.19", ["backend", "frontend", "infra"], "Look for: unvetted third-party dependencies, missing SBOMs, no dependency pinning, packages from untrusted registries"),
        ChecklistItem("ISO05", "Logging (A.8.15)", "Check for security event logging", "MEDIUM", "config", "ISO", "A.8.15", ["backend", "api"], "Look for: missing security event logs, PII in log files, logs without timestamps, missing centralized logging, no log retention policy"),
        ChecklistItem("ISO06", "Data Masking (A.8.11)", "Check for PII protection and data masking", "HIGH", "pii", "ISO", "A.8.11", ["backend", "api"], "Look for: PII stored without encryption, PII in logs, PII in error messages, missing data classification, PII transmitted without TLS"),
    ],
)

INFRA_CHECKLIST = Checklist(
    name="Infrastructure Security (Dockerfile + Terraform)",
    description="Security checks for infrastructure-as-code: Docker, Terraform, Kubernetes",
    version="1.0",
    items=[
        ChecklistItem("INFRA01", "Docker: Running as Root", "Check if containers run as root user", "HIGH", "config", "CWE", "CWE-250", ["infra"], "Look for: missing USER directive in Dockerfile, processes running as root, containers with privileged flag"),
        ChecklistItem("INFRA02", "Docker: Secrets in Image", "Check for secrets baked into Docker images", "CRITICAL", "config", "CWE", "CWE-798", ["infra"], "Look for: COPY .env, ARG with secrets, ENV with API keys, passwords in Dockerfile, secrets in build args"),
        ChecklistItem("INFRA03", "Docker: Unpinned Base Images", "Check for non-deterministic base images", "MEDIUM", "supply_chain", "CWE", "CWE-829", ["infra"], "Look for: FROM image:latest, FROM image without tag, missing SHA256 digest pinning, using deprecated base images"),
        ChecklistItem("INFRA04", "Terraform: Overly Permissive IAM", "Check for wildcard IAM permissions", "CRITICAL", "auth", "CWE", "CWE-732", ["infra"], "Look for: IAM policies with Action: *, Resource: *, overly broad permissions, missing conditions, admin access without MFA"),
        ChecklistItem("INFRA05", "Terraform: Public Resources", "Check for unintentionally public resources", "HIGH", "config", "CWE", "CWE-284", ["infra"], "Look for: S3 buckets with public access, security groups with 0.0.0.0/0 ingress, public subnets for databases, RDS without encryption"),
        ChecklistItem("INFRA06", "Terraform: Hardcoded Secrets", "Check for secrets in Terraform files", "CRITICAL", "config", "CWE", "CWE-798", ["infra"], "Look for: passwords in .tf files, API keys in variables with defaults, sensitive values not marked as sensitive, plaintext in terraform.tfstate"),
        ChecklistItem("INFRA07", "Missing HTTPS/TLS", "Check for unencrypted communication", "HIGH", "crypto", "CWE", "CWE-319", ["infra"], "Look for: HTTP listeners without redirect, load balancers without TLS, missing certificate configuration, weak TLS versions"),
    ],
)

MOBILE_CHECKLIST = Checklist(
    name="Mobile Application Security (OWASP MASVS)",
    description="Mobile app security checks based on OWASP Mobile Application Security Verification Standard",
    version="2.0",
    items=[
        ChecklistItem("MOB01", "Insecure Data Storage", "Check for sensitive data stored insecurely on device", "HIGH", "crypto", "OWASP", "MASVS-STORAGE-1", ["mobile"], "Look for: plaintext credentials in SharedPreferences/UserDefaults, sensitive data in SQLite without encryption, API keys in code, tokens stored insecurely"),
        ChecklistItem("MOB02", "Insecure Communication", "Check for unprotected data transmission", "HIGH", "crypto", "OWASP", "MASVS-NETWORK-1", ["mobile"], "Look for: HTTP without TLS, missing certificate pinning, accepting self-signed certificates, cleartext traffic allowed in manifest"),
        ChecklistItem("MOB03", "Insecure Authentication", "Check for weak authentication on mobile", "CRITICAL", "auth", "OWASP", "MASVS-AUTH-1", ["mobile"], "Look for: biometric bypass, missing session expiry, tokens without refresh rotation, local-only authentication without server verification"),
        ChecklistItem("MOB04", "Code Tampering", "Check for missing integrity verification", "MEDIUM", "config", "OWASP", "MASVS-RESILIENCE-1", ["mobile"], "Look for: missing root/jailbreak detection, no code signing verification, missing integrity checks, debugging enabled in release builds"),
        ChecklistItem("MOB05", "Hardcoded Secrets", "Check for secrets embedded in mobile app code", "CRITICAL", "config", "CWE", "CWE-798", ["mobile"], "Look for: API keys in source code, hardcoded passwords, encryption keys in code, backend URLs with credentials"),
    ],
)

# ── Registry ────────────────────────────────────────────────────────────

_CHECKLISTS: dict[str, Checklist] = {
    "owasp-api": OWASP_API_CHECKLIST,
    "owasp-web": OWASP_WEB_CHECKLIST,
    "nist": NIST_CHECKLIST,
    "iso27001": ISO27001_CHECKLIST,
    "infra": INFRA_CHECKLIST,
    "mobile": MOBILE_CHECKLIST,
}

_CODEBASE_TYPE_MAP: dict[str, list[str]] = {
    "api": ["owasp-api", "nist", "iso27001"],
    "backend": ["owasp-web", "nist", "iso27001"],
    "frontend": ["owasp-web", "iso27001"],
    "mobile": ["mobile", "owasp-web"],
    "infra": ["infra", "nist"],
}


def list_checklists() -> dict[str, str]:
    return {k: v.name for k, v in _CHECKLISTS.items()}


def list_categories() -> dict[str, list[str]]:
    return {k: v for k, v in _CODEBASE_TYPE_MAP.items()}


def get_checklist(name: str) -> Checklist | None:
    return _CHECKLISTS.get(name)


def get_checklists_for_codebase(codebase_type: str) -> list[Checklist]:
    names = _CODEBASE_TYPE_MAP.get(codebase_type, [])
    return [_CHECKLISTS[n] for n in names if n in _CHECKLISTS]


def get_combined_checklist(codebase_type: str) -> Checklist:
    """Get a single combined checklist for a codebase type."""
    checklists = get_checklists_for_codebase(codebase_type)
    all_items = []
    for cl in checklists:
        all_items.extend(cl.items)
    return Checklist(
        name=f"Combined: {codebase_type}",
        description=f"All applicable checks for {codebase_type} codebases",
        version="combined",
        items=all_items,
    )


def load_custom_checklist(path: str | Path) -> Checklist:
    """Load a checklist from a JSON file."""
    data = json.loads(Path(path).read_text())
    return Checklist.from_json(data)
