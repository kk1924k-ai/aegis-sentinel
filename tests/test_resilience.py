"""Resilience & fault-injection tests for AEGIS — реальные сбои"""
import sys
sys.path.insert(0, ".")
from fastapi.testclient import TestClient
from agents.aegis_webhook import app, _reset_webhook_state
from agents.nevermined_skill import _reset_security_state
from core.analyzer import AegisAnalyzer

def ok(m): print(f"✅ {m}")
def fail(m): print(f"❌ {m}"); sys.exit(1)

client = TestClient(app)
code_vuln = open("tests/fixtures/VulnerableBank.sol", encoding="utf-8").read()

# 1. malformed JSON -> 400/422 no crash
_reset_webhook_state(); _reset_security_state()
r = client.post("/api/v1/aegis-scan", content="{not valid json", headers={"Content-Type":"application/json"})
assert r.status_code in (400,422), f"malformed json expected 400/422 got {r.status_code} {r.text[:200]}"
ok(f"malformed JSON -> {r.status_code} no crash")

# 2. empty body -> 400
_reset_webhook_state(); _reset_security_state()
r = client.post("/api/v1/aegis-scan", json={})
assert r.status_code == 400, r.text
ok("empty body -> 400")

# 3. code = empty string -> 400
r = client.post("/api/v1/aegis-scan", json={"code": ""})
assert r.status_code == 400, r.text
ok("empty code string -> 400")

# 4. code = whitespace only -> 400
r = client.post("/api/v1/aegis-scan", json={"code": "   \n\t  "})
assert r.status_code == 400, r.text
ok("whitespace code -> 400")

# 5. oversize 200KB+1 -> 413
big = "a" * (200*1024+1)
r = client.post("/api/v1/aegis-scan", json={"code": big})
assert r.status_code == 413, f"expected 413 got {r.status_code}"
ok("oversize 200KB+1 -> 413")

# 6. 1MB bomb -> 413 no crash / no OOM
big1m = "x" * (1024*1024)
r = client.post("/api/v1/aegis-scan", json={"code": big1m})
assert r.status_code == 413, r.text
ok("1MB bomb -> 413 no crash")

# 7. Z3 bomb: 2000 requires — must not hang, returns 200 or 400 quickly
_reset_webhook_state(); _reset_security_state()
z3_bomb = "pragma solidity ^0.8.0; contract Bomb { function f() public { " + "require(true); "*2000 + "} }"
r = client.post("/api/v1/aegis-scan", json={"code": z3_bomb, "free_trial": True})
assert r.status_code in (200, 400, 413), f"z3 bomb unexpected {r.status_code} {r.text[:300]}"
# analyzer must finish < 10s (TestClient is sync)
if r.status_code == 200:
    assert "score" in r.json()["report"]
    ok(f"Z3 bomb 2000 requires -> 200 score {r.json()['report']['score']} no hang")
else:
    ok(f"Z3 bomb -> {r.status_code} handled")

# 8. weird chain values -> 400
for ch in ["solana", "eip155:1", "eip155:137", "'; DROP TABLE", "<script>", ""]:
    _reset_webhook_state(); _reset_security_state()
    r = client.post("/api/v1/aegis-scan", json={"code": code_vuln, "chain": ch})
    # empty chain defaults to base? our webhook defaults base, but skill checks ALLOWED_CHAINS
    # if ch=="" -> defaults to "base" -> should be 402 (needs payment) not 400
    if ch == "":
        assert r.status_code in (400,402), r.text
    else:
        assert r.status_code == 400, f"chain {ch!r} expected 400 got {r.status_code} {r.text[:200]}"
ok("weird chain injection -> 400 blocked")

# 9. signature injection payloads -> 402 blocked no crash
_reset_webhook_state(); _reset_security_state()
for sig in ["0x'; DROP TABLE users; --", "0x<script>alert(1)</script>", "0x" + "ZZ"*20, "short", "0x", "0x" + "ab"*500]:
    r = client.post("/api/v1/aegis-scan", json={"code": code_vuln}, headers={"payment-signature": sig})
    assert r.status_code == 402, f"sig {sig[:30]} expected 402 got {r.status_code} {r.text[:200]}"
ok("sig injection payloads -> 402 blocked no crash")

# 10. headers case variations + missing
_reset_webhook_state(); _reset_security_state()
sig_valid = "0x" + "aa"*20
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln}, headers={"Payment-Signature": sig_valid})
assert r.status_code == 200, r.text
ok("Payment-Signature case-insensitive -> 200")
# replay same sig with different case -> should be 402 replay
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln}, headers={"payment-signature": sig_valid})
assert r.status_code == 402, "replay must be 402"
ok("replay same sig second time -> 402")

# 11. body must be JSON object not array
_reset_webhook_state(); _reset_security_state()
r = client.post("/api/v1/aegis-scan", json=["not","object"])
assert r.status_code == 400, r.text
ok("body array -> 400")

# 12. concurrently missing code field
r = client.post("/api/v1/aegis-scan", json={"chain":"base","free_trial":True})
assert r.status_code == 400, r.text
ok("missing code field -> 400")

# 13. subscription without body
_reset_webhook_state(); _reset_security_state()
r = client.post("/api/v1/aegis-subscribe", content="not json", headers={"Content-Type":"application/json"})
# our handler does try/except body = {} on parse fail -> then 402
assert r.status_code == 402, f"sub malformed expected 402 got {r.status_code} {r.text[:200]}"
ok("sub malformed JSON -> 402 no crash")

# 14. health must never 500
r = client.get("/health")
assert r.status_code == 200 and r.json()["status"] == "ok"
ok("GET /health -> 200 stable")

# 15. analyzer direct: code with no solidity -> should not crash
a = AegisAnalyzer()
rep = a.analyze("hello world not solidity", "test.txt", "base")
assert rep.score >= 0
ok(f"analyzer garbage input -> score {rep.score} no crash")

print("\n=== ALL RESILIENCE TESTS PASSED ===")
