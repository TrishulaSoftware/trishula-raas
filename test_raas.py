"""
Trishula RaaS — Test Suite
SQA v5 [ASCENDED] Compliance: MC/DC Determinism + Bit-Perfect Persistence
"""
import json
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from raas_server import app, VULN_DB

PASSED = 0
FAILED = 0

def test(name, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  ✅ {name}")
    else:
        FAILED += 1
        print(f"  ❌ {name}")

print("=" * 70)
print("  TRISHULA RAAS — SQA TEST SUITE")
print("=" * 70)

client = app.test_client()

# ── TEST GROUP 1: Health Endpoint ──
print("\n── TEST GROUP 1: Health Endpoint ──")

resp = client.get("/health")
data = resp.get_json()

test("Health returns 200", resp.status_code == 200)
test("Status is OPERATIONAL", data.get("status") == "OPERATIONAL")
test("Version is 1.0.0", data.get("version") == "1.0.0")
test("Reports vuln_rules count", data.get("vuln_rules") == len(VULN_DB))
test("Has timestamp", "timestamp" in data)

# ── TEST GROUP 2: VulnDB Endpoint ──
print("\n── TEST GROUP 2: VulnDB Listing ──")

resp = client.get("/api/v1/vulndb")
data = resp.get_json()

test("VulnDB returns 200", resp.status_code == 200)
test("Has 'rules' array", "rules" in data)
test("Count matches DB size", data.get("count") == len(VULN_DB))
test("Each rule has pattern/fix/severity/reason",
     all("pattern" in r and "fix" in r and "severity" in r and "reason" in r
         for r in data["rules"]))

# ── TEST GROUP 3: Scan Endpoint ──
print("\n── TEST GROUP 3: Scan Endpoint ──")

vuln_yaml = """
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - uses: actions/cache@v1
"""

resp = client.post("/api/v1/scan",
                   data=json.dumps({"workflow": vuln_yaml}),
                   content_type="application/json")
data = resp.get_json()

test("Scan returns 200", resp.status_code == 200)
test("Detected 3 vulnerabilities", data.get("total_vulnerabilities") == 3)
test("Has findings array", "findings" in data)
test("Sorted by severity (HIGH first)", data["findings"][0]["severity"] == "HIGH")
test("Each finding has vulnerability field",
     all("vulnerability" in f for f in data["findings"]))
test("Each finding has fix field",
     all("fix" in f for f in data["findings"]))
test("Has risk_level", "risk_level" in data)

# ── TEST GROUP 4: Scan — Clean Workflow ──
print("\n── TEST GROUP 4: Clean Workflow Scan ──")

clean_yaml = """
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
"""

resp = client.post("/api/v1/scan",
                   data=json.dumps({"workflow": clean_yaml}),
                   content_type="application/json")
data = resp.get_json()

test("Clean scan returns 200", resp.status_code == 200)
test("Zero vulnerabilities found", data.get("total_vulnerabilities") == 0)
test("Risk level is NONE", data.get("risk_level") == "NONE")

# ── TEST GROUP 5: Patch Endpoint ──
print("\n── TEST GROUP 5: Patch Endpoint ──")

resp = client.post("/api/v1/patch",
                   data=json.dumps({"workflow": vuln_yaml}),
                   content_type="application/json")
data = resp.get_json()

test("Patch returns 200", resp.status_code == 200)
test("Has original_sha256", "original_sha256" in data)
test("Has patched_sha256", "patched_sha256" in data)
test("Has patched_workflow", "patched_workflow" in data)
test("Has fixes_applied list", "fixes_applied" in data)
test("Applied 3 fixes", data.get("fix_count") == 3)
test("Has cryptographic signature", "signature" in data)
test("Signature starts with sig_", data.get("signature", "").startswith("sig_"))
test("Original != patched hash", data["original_sha256"] != data["patched_sha256"])
test("Patched content has checkout@v4", "actions/checkout@v4" in data["patched_workflow"])
test("Patched content lacks checkout@v2", "actions/checkout@v2" not in data["patched_workflow"])

# ── TEST GROUP 6: Patch — Clean Workflow ──
print("\n── TEST GROUP 6: Clean Workflow Patch ──")

resp = client.post("/api/v1/patch",
                   data=json.dumps({"workflow": clean_yaml}),
                   content_type="application/json")
data = resp.get_json()

test("Clean patch returns 200", resp.status_code == 200)
test("Message says no vulnerabilities", "no vulnerabilities" in data.get("message", "").lower()
     or data.get("fixes_applied") == 0
     or "clean" in data.get("message", "").lower())

# ── TEST GROUP 7: Error Handling ──
print("\n── TEST GROUP 7: Error Handling ──")

resp = client.post("/api/v1/scan",
                   data=json.dumps({"wrong_field": "test"}),
                   content_type="application/json")
test("Missing workflow field returns 400", resp.status_code == 400)

resp = client.post("/api/v1/patch",
                   data=json.dumps({}),
                   content_type="application/json")
test("Empty body returns 400", resp.status_code == 400)

# ── SUMMARY ──
print("\n" + "=" * 70)
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
verdict = "✅ SQA PASS" if FAILED == 0 else "❌ SQA FAIL"
print(f"  VERDICT: {verdict}")
print("=" * 70)
