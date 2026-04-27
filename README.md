# Trishula Reforge-as-a-Service (RaaS)

**Autonomous CI/CD workflow remediation via REST API. Submit broken YAML, get back a patched version with a cryptographic signature.**

[![CI](https://github.com/TrishulaSoftware/trishula-raas/actions/workflows/ci.yml/badge.svg)](https://github.com/TrishulaSoftware/trishula-raas/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 34/34](https://img.shields.io/badge/tests-34%2F34-brightgreen.svg)]()
[![SQA v5 ASCENDED](https://img.shields.io/badge/SQA-v5_ASCENDED-gold.svg)]()

---

## The Problem

**CI/CD pipelines are breaking at scale, and nobody has an API to fix them.**

| Stat | Source | Date |
|:--|:--|:--|
| **43%** of AI-generated code needs manual debugging in production | Lightrun | Apr 2026 |
| **5%** of AI model requests failing in production | Datadog | Apr 2026 |
| **54%** of incident resolution relies on "tribal knowledge" | Lightrun | Apr 2026 |
| Tier-1 cloud BGP route leak caused cascading global failure | FrontierAffairs | Apr 2026 |
| Microsoft Outlook global auth failure from a config change | TechRadar | Apr 2026 |

When a CI/CD pipeline breaks, teams spend hours manually diagnosing YAML configurations, tracking down deprecated actions, and testing patches. There is **no API** that accepts broken workflow YAML and returns a verified, signed patch.

### What Exists vs. What's Missing

| Service | Scans | Patches | API | Signatures | Self-Healing |
|:--|:--|:--|:--|:--|:--|
| Snyk | ✅ | ❌ PRs only | ⚠️ | ❌ | ❌ |
| Dependabot | ✅ | ❌ PRs only | ❌ | ❌ | ❌ |
| Renovate | ✅ | ❌ PRs only | ❌ | ❌ | ❌ |
| **Trishula RaaS** | **✅** | **✅ Full patched YAML** | **✅ REST** | **✅ SHA3-512** | **✅** |

**Nobody offers autonomous patch generation with cryptographic signing as an API.**

---

## What This API Does

Submit workflow YAML → Get back a scan report + patched file + cryptographic signature.

### Endpoints

| Method | Path | Description |
|:--|:--|:--|
| `POST` | `/api/v1/scan` | Scan workflow YAML for vulnerabilities |
| `POST` | `/api/v1/patch` | Scan + patch workflow YAML (returns fixed content) |
| `GET` | `/api/v1/vulndb` | List all 17 known vulnerability rules |
| `GET` | `/health` | Service health check |

---

## Quick Start

```bash
pip install -r requirements.txt
python raas_server.py
```

### Scan a Workflow

```bash
curl -X POST http://localhost:8443/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"workflow": "uses: actions/checkout@v2\nuses: docker/build-push-action@v1"}'
```

Response:
```json
{
  "findings": [
    {
      "vulnerability": "actions/checkout@v2",
      "fix": "actions/checkout@v4",
      "severity": "MEDIUM",
      "reason": "Uses Node.js 16 (approaching EOL)",
      "occurrences": 1
    },
    {
      "vulnerability": "docker/build-push-action@v1",
      "fix": "docker/build-push-action@v5",
      "severity": "HIGH",
      "reason": "Lacks provenance attestation and SBOM support",
      "occurrences": 1
    }
  ],
  "total_vulnerabilities": 2,
  "risk_level": "HIGH"
}
```

### Patch a Workflow

```bash
curl -X POST http://localhost:8443/api/v1/patch \
  -H "Content-Type: application/json" \
  -d '{"workflow": "uses: actions/checkout@v2"}'
```

Response:
```json
{
  "original_sha256": "abc123...",
  "patched_sha256": "def456...",
  "patched_workflow": "uses: actions/checkout@v4",
  "fixes_applied": [
    {"from": "actions/checkout@v2", "to": "actions/checkout@v4", "severity": "MEDIUM"}
  ],
  "signature": "sig_789...",
  "generated_at": "2026-04-22T04:00:00Z"
}
```

---

## Proof It Works: 34 Tests

```
CATEGORY: Server initialization .............. PASS
CATEGORY: POST /api/v1/scan .................. PASS
CATEGORY: POST /api/v1/patch ................. PASS
CATEGORY: GET /api/v1/vulndb ................. PASS
CATEGORY: GET /health ........................ PASS
CATEGORY: Error handling ..................... PASS
CATEGORY: Signature verification ............. PASS
CATEGORY: Edge cases ......................... PASS

TOTAL: 34/34 PASSED | VERDICT: SQA_v5_ASCENDED
```

```bash
python test_raas.py
```

---

## SQA v5 ASCENDED Compliance

| SQA Pillar | Implementation | Evidence |
|:--|:--|:--|
| **Pillar 1: MC/DC Determinism** | Same workflow input always produces same patched output and same SHA. Scan results are deterministic. | Determinism tests |
| **Pillar 2: Bit-Perfect Persistence** | SHA-256 hashes of original and patched files. SHA3-512 signatures on every patch. | Signature tests |
| **Pillar 3: Adversarial Self-Audit** | Invalid JSON rejected. Empty workflows handled. Malformed YAML produces structured error. | Error handling tests |
| **Pillar 4: Zero-Leak Egress** | No credentials in responses. Health endpoint reveals no internals. | API security review |

---

## Docker

```bash
docker build -t trishula-raas .
docker run -p 8443:8443 trishula-raas
```

### Docker Compose

```yaml
services:
  raas:
    build: .
    ports:
      - "8443:8443"
    restart: unless-stopped
```

---

## License

MIT
