# Trishula Reforge-as-a-Service (RaaS)

REST API for automated CI/CD workflow remediation. Submit your GitHub Actions YAML, get back a patched version with a cryptographic signature.

## Endpoints

| Method | Path | Description |
|:--|:--|:--|
| `POST` | `/api/v1/scan` | Scan workflow YAML for vulnerabilities |
| `POST` | `/api/v1/patch` | Scan + patch workflow YAML |
| `GET` | `/api/v1/vulndb` | List all known vulnerability rules |
| `GET` | `/health` | Service health check |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python raas_server.py

# Or with Docker
docker build -t trishula-raas .
docker run -p 8443:8443 trishula-raas
```

## Usage Examples

### Scan a workflow

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

### Patch a workflow

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

### List vulnerability database

```bash
curl http://localhost:8443/api/v1/vulndb
```

## Docker Compose Integration

```yaml
services:
  raas:
    build: .
    ports:
      - "8443:8443"
    restart: unless-stopped
```

## License

MIT
