"""Real security & earning tests for hardened AEGIS"""
import time, hashlib, sys
sys.path.insert(0, ".")
from agents.nevermined_skill import NeverminedSkillWrapper, _reset_security_state
from agents.aegis_webhook import _reset_webhook_state
from core.analyzer import AegisAnalyzer
from core.smt_prover import prove_invariant
from agents.immunefi_hunter import ImmunefiHunter
from social.farcaster_bot import FarcasterBountyBot
from infra.dash_metrics import Dashboard
from infra.gas_vault import GasVault

def ok(msg): print(f"✅ {msg}")
def fail(msg): print(f"❌ {msg}"); sys.exit(1)

_reset_security_state()
_reset_webhook_state()

code_vuln = open("tests/fixtures/VulnerableBank.sol", encoding="utf-8").read()
code_safe = open("tests/fixtures/SafeVault.sol", encoding="utf-8").read()

w = NeverminedSkillWrapper()

# 1. publish validation
try:
    w.publish_service()
    ok("publish_service LIVE")
except Exception as e: fail(f"publish {e}")

# 2. 400 no code
r = w.handle_scan_request({"code":""}, {})
assert r["status"]==400, r
ok("400 no code")

# 3. 413 oversize
big = "a"* (200*1024+1)
r = w.handle_scan_request({"code": big}, {})
assert r["status"]==413, r
ok("413 oversize >200KB blocked")

# 4. 400 bad chain
r = w.handle_scan_request({"code": code_vuln, "chain":"solana"}, {})
assert r["status"]==400, r
ok("400 unsupported chain blocked")

# 5. 402 no payment
r = w.handle_scan_request({"code": code_vuln}, {})
assert r["status"]==402 and r["payment"]["amount"]=="5" and r["payment"]["recipient"]=="0xDC056FcF4d3442110862E7eA7c02b5E81eAD4B1F"
ok("402 paywall without sig")

# 6. 402 invalid sig format
r = w.handle_scan_request({"code": code_vuln}, {"payment-signature":"short"})
assert r["status"]==402, r
ok("402 invalid sig format blocked")

# 7. 402 invalid hex
r = w.handle_scan_request({"code": code_vuln}, {"payment-signature":"0xZZZZZZZZZZZZZZZZZZZZ"})
assert r["status"]==402, r
ok("402 non-hex sig blocked")

# 8. free_trial 200
r = w.handle_scan_request({"code": code_vuln, "free_trial":True}, {})
assert r["status"]==200 and r["report"]["score"]==33 and "anchor" in r and r["confidential"]==True
ok(f"200 free_trial score {r['report']['score']} anchor {r['anchor'][:12]}...")

# 9. paid 200
sig1 = "0x" + "ab"*20
r = w.handle_scan_request({"code": code_vuln}, {"payment-signature": sig1})
assert r["status"]==200 and r["payment"]["earned"]=="5 USDC" and r["payment"]["replay_protected"]==True
ok(f"200 paid sig1 earned {r['payment']['earned']}")

# 10. replay same sig -> 402
r = w.handle_scan_request({"code": code_vuln}, {"payment-signature": sig1})
assert r["status"]==402, f"replay should be 402 got {r}"
ok("402 replay protection same sig blocked")

# 11. case-insensitive header
sig2 = "0x" + "cd"*20
r = w.handle_scan_request({"code": code_vuln}, {"Payment-Signature": sig2})
assert r["status"]==200, r
ok("200 case-insensitive Payment-Signature")

# 12. SafeVault score
sig3 = "0x" + "ef"*20
r = w.handle_scan_request({"code": code_safe}, {"payment-signature": sig3})
assert r["status"]==200 and r["report"]["score"]>=80, r
ok(f"SafeVault score {r['report']['score']} >=80")

# 13. subscription 402
_reset_security_state()
r = w.handle_subscription({}, {})
assert r["status"]==402 and r["payment"]["amount"]=="299", r
ok("sub 402 without sig")

# 14. subscription 200
sig4 = "0x" + "11"*20
r = w.handle_subscription({"payment-signature": sig4}, {})
assert r["status"]==200 and "sub_" in r["subscription_id"] and r["earned"]=="299 USDC"
ok(f"sub 200 {r['subscription_id']} earned {r['earned']}")

# 15. sub replay
r = w.handle_subscription({"payment-signature": sig4}, {})
assert r["status"]==402, r
ok("sub replay blocked")

# 16. Webhook TestClient hardened checks
from fastapi.testclient import TestClient
from agents.aegis_webhook import app
_reset_security_state()
_reset_webhook_state()
client = TestClient(app)

# health
r = client.get("/health")
assert r.status_code==200 and r.json()["version"]=="2.1-hardened"
ok("webhook GET /health 2.1-hardened")

# invalid json body -> 400 handled by json exception? our endpoint returns 400
# unsupported chain via webhook -> 400
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln, "chain":"solana"})
assert r.status_code==400, r.text
ok("webhook 400 bad chain")

# oversize via webhook -> 413
r = client.post("/api/v1/aegis-scan", json={"code": big})
assert r.status_code==413, r.text
ok("webhook 413 oversize")

# free_trial quota 3/day
_reset_webhook_state(); _reset_security_state()
for i in range(3):
    r = client.post("/api/v1/aegis-scan", json={"code": code_vuln, "free_trial": True})
    assert r.status_code==200, f"free trial {i} failed {r.text}"
ok("webhook 3 free_trial OK")
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln, "free_trial": True})
assert r.status_code==429, f"4th free trial should be 429 got {r.status_code} {r.text}"
ok("webhook 4th free_trial 429 quota blocked -> must pay")

# rate limit 10/min
_reset_webhook_state(); _reset_security_state()
for i in range(10):
    client.post("/api/v1/aegis-scan", json={"code": "pragma solidity ^0.8.0;"}, headers={"payment-signature": f"0x{'a'*40}{i}"})
# 11th should be 429 or 402 depending on sig validity but rate limit triggers
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln}, headers={"payment-signature": "0x" + "bb"*20})
# after 10 in same minute, next is rate limited
assert r.status_code==429, f"rate limit expected 429 got {r.status_code} {r.text}"
ok("webhook rate limit 10/min -> 429 blocked")

# webhook paid flow 402->200
_reset_webhook_state(); _reset_security_state()
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln})
assert r.status_code==402, r.text
ok("webhook 402 without sig")
r = client.post("/api/v1/aegis-scan", json={"code": code_vuln}, headers={"payment-signature": "0x" + "cc"*20})
assert r.status_code==200 and r.json()["report"]["score"]==33
ok("webhook 200 paid + score 33")

# hunters
h = ImmunefiHunter()
bounties = h.fetch_new_bounties()
assert len(bounties)>=2
ok(f"Immunefi hunter fetch {len(bounties)} bounties")
for b in bounties:
    res = h.analyze_bounty(b)
    assert res["status"]=="queued_for_scan"
ok("Immunefi analyze_bounty queued")
# scan code for bounty
rep = h.scan_code_for_bounty(code_vuln)
assert rep.score==33
ok(f"Immunefi scan_code score {rep.score}")

# farcaster
fb = FarcasterBountyBot({"farcaster_signer_uuid":"mock","neynar_api_key":"mock"})
casts = fb.search_bounties()
assert len(casts)>=2
ok(f"Farcaster search {len(casts)} casts")
reply = fb.format_reply({"score":33,"vulns":4,"hash":"8861a7065ace1234"})
assert "🚨" in reply and "33/100" in reply and "pay-per-scan" in reply
ok(f"Farcaster format_reply {reply[:40]}...")
text = fb.respond_with_scan(casts[0]["hash"], {"score":33,"vulns":4,"hash":"8861a706"})
assert "Score" in text
ok("Farcaster respond_with_scan")

# dashboard
d = Dashboard()
d.record_scan("nevermined", 33, revenue=5.0, gas_cost=0.02)
d.record_scan("nevermined", 85, revenue=5.0, gas_cost=0.01)
d.record_subscription(299)
out = d.render()
assert "Total Scans:      2" in out and "Earnings" in out
ok("Dashboard 2 scans + 1 sub rendered")
print(out)

# gas vault
gv = GasVault()
st = gv.status()
assert st["vault"]=="0xDC056FcF4d3442110862E7eA7c02b5E81eAD4B1F"
acts = gv.auto_replenish()
ok(f"GasVault auto_replenish {acts[0][:50]}")

# smt
smt = prove_invariant(code_vuln, "balances[msg.sender] >=0")
assert "proof_hash" in smt
ok(f"SMT solver {smt.get('solver')} proof {smt['proof_hash'][:8]}")

print("\n=== ALL HARDENED TESTS PASSED ===")
