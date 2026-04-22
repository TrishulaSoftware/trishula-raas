"""
Trishula Reforge-as-a-Service (RaaS)
REST API that accepts GitHub workflow YAML and returns signed remediation patches.

Endpoints:
    POST /api/v1/scan      — Submit workflow YAML, get vulnerability report
    POST /api/v1/patch      — Submit workflow YAML, get patched version + signature
    GET  /api/v1/vulndb     — List all known vulnerability rules
    GET  /health            — Service health check
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify

LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ RAAS │ %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("raas")

app = Flask(__name__)

# ── Vulnerability Database ──────────────────────────────────────────
VULN_DB = {
    "actions/checkout@v1": {
        "fix": "actions/checkout@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No submodule security."
    },
    "actions/checkout@v2": {
        "fix": "actions/checkout@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL). Lacks OIDC support."
    },
    "actions/checkout@v3": {
        "fix": "actions/checkout@v4",
        "severity": "LOW",
        "reason": "Missing latest security hardening."
    },
    "actions/setup-python@v2": {
        "fix": "actions/setup-python@v5",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 12 (EOL)."
    },
    "actions/setup-python@v3": {
        "fix": "actions/setup-python@v5",
        "severity": "LOW",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/setup-node@v1": {
        "fix": "actions/setup-node@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No caching."
    },
    "actions/setup-node@v2": {
        "fix": "actions/setup-node@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/setup-java@v1": {
        "fix": "actions/setup-java@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL)."
    },
    "actions/upload-artifact@v1": {
        "fix": "actions/upload-artifact@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). No compression."
    },
    "actions/upload-artifact@v2": {
        "fix": "actions/upload-artifact@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "actions/download-artifact@v1": {
        "fix": "actions/download-artifact@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL)."
    },
    "actions/cache@v1": {
        "fix": "actions/cache@v4",
        "severity": "HIGH",
        "reason": "Uses Node.js 12 (EOL). Cache poisoning risks."
    },
    "actions/cache@v2": {
        "fix": "actions/cache@v4",
        "severity": "MEDIUM",
        "reason": "Uses Node.js 16 (approaching EOL)."
    },
    "docker/build-push-action@v1": {
        "fix": "docker/build-push-action@v5",
        "severity": "HIGH",
        "reason": "Lacks provenance attestation and SBOM support."
    },
    "docker/build-push-action@v2": {
        "fix": "docker/build-push-action@v5",
        "severity": "MEDIUM",
        "reason": "Missing latest buildx and attestation features."
    },
}

# Request counter for metrics
_request_count = {"scan": 0, "patch": 0}


def _sign_content(content: str) -> str:
    """SHA3-512 signature for patch integrity verification."""
    return f"sig_{hashlib.sha3_512(content.encode()).hexdigest()[:64]}"


@app.route("/health", methods=["GET"])
def health():
    """Service health check."""
    return jsonify({
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "vuln_rules": len(VULN_DB),
        "requests_processed": _request_count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/v1/vulndb", methods=["GET"])
def list_vulns():
    """List all known vulnerability rules."""
    rules = []
    for pattern, rule in VULN_DB.items():
        rules.append({
            "pattern": pattern,
            "fix": rule["fix"],
            "severity": rule["severity"],
            "reason": rule["reason"]
        })
    return jsonify({"rules": rules, "count": len(rules)})


@app.route("/api/v1/scan", methods=["POST"])
def scan_workflow():
    """
    Scan workflow YAML for known vulnerabilities.

    Request body:
        {"workflow": "yaml content as string"}

    Returns:
        List of detected vulnerabilities with severity and fix info.
    """
    data = request.get_json()
    if not data or "workflow" not in data:
        return jsonify({"error": "Missing 'workflow' field in request body"}), 400

    workflow = data["workflow"]
    findings = []

    for pattern, rule in VULN_DB.items():
        count = workflow.count(pattern)
        if count > 0:
            findings.append({
                "vulnerability": pattern,
                "fix": rule["fix"],
                "severity": rule["severity"],
                "reason": rule["reason"],
                "occurrences": count
            })

    # Sort by severity
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    _request_count["scan"] += 1
    logger.info(f"[SCAN] {len(findings)} vulnerabilities detected")

    return jsonify({
        "findings": findings,
        "total_vulnerabilities": len(findings),
        "risk_level": findings[0]["severity"] if findings else "NONE",
        "scanned_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/v1/patch", methods=["POST"])
def patch_workflow():
    """
    Scan and patch a workflow YAML file.

    Request body:
        {"workflow": "yaml content as string"}

    Returns:
        Patched YAML content with SHA-256 hashes and a cryptographic signature.
    """
    data = request.get_json()
    if not data or "workflow" not in data:
        return jsonify({"error": "Missing 'workflow' field in request body"}), 400

    original = data["workflow"]
    patched = original
    fixes = []

    for pattern, rule in VULN_DB.items():
        if pattern in patched:
            patched = patched.replace(pattern, rule["fix"])
            fixes.append({
                "from": pattern,
                "to": rule["fix"],
                "severity": rule["severity"],
                "reason": rule["reason"]
            })

    if not fixes:
        return jsonify({
            "message": "No vulnerabilities found. Workflow is clean.",
            "fixes_applied": 0,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        })

    _request_count["patch"] += 1
    logger.info(f"[PATCH] {len(fixes)} fixes applied")

    return jsonify({
        "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "patched_sha256": hashlib.sha256(patched.encode()).hexdigest(),
        "patched_workflow": patched,
        "fixes_applied": fixes,
        "fix_count": len(fixes),
        "signature": _sign_content(patched),
        "generated_at": datetime.now(timezone.utc).isoformat()
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8443))
    logger.info(f"RaaS starting on port {port}")
    app.run(host="0.0.0.0", port=port)
