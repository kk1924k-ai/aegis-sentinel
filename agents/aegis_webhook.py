"""AEGIS webhook — FastAPI bridge for Koka x402 (HARDENED)
Run: uvicorn agents.aegis_webhook:app --port 8090 --host 0.0.0.0
Security: IP rate-limit, free_trial quota 3/IP/day, input validation, replay protection via nevermined_skill
"""
import time
import hashlib
from collections import defaultdict, deque
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI(title="AEGIS Sentinel x402", version="2.1-hardened")

# In-memory rate limit & quota (process-local)
# rate: 10 req/min per IP, free_trial: 3/day per IP
RATE_LIMIT_PER_MIN = 10
FREE_TRIAL_PER_DAY = 3
MAX_CODE_BYTES = 200 * 1024
ALLOWED_CHAINS = {"base", "ethereum", "arbitrum", "polygon", "bnb", "avalanche", "optimism", "linea", "scroll"}

_req_log: dict[str, deque] = defaultdict(deque)  # ip -> deque[timestamps]
_free_trial_log: dict[str, list] = defaultdict(list)  # ip -> list[timestamps]
_blocked_ips: dict[str, float] = {}  # ip -> unblock_time

def _client_ip(request: Request) -> str:
    # honor X-Forwarded-For when behind Koka proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _is_rate_limited(ip: str) -> tuple[bool, str]:
    now = time.time()
    # check blocked
    if ip in _blocked_ips and now < _blocked_ips[ip]:
        return True, f"IP blocked until {int(_blocked_ips[ip])}"
    elif ip in _blocked_ips and now >= _blocked_ips[ip]:
        del _blocked_ips[ip]
    dq = _req_log[ip]
    # purge older than 60s
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_PER_MIN:
        # block for 60s on abuse
        _blocked_ips[ip] = now + 60
        return True, f"Rate limit {RATE_LIMIT_PER_MIN}/min exceeded"
    dq.append(now)
    return False, ""

def _free_trial_allowed(ip: str) -> tuple[bool, str]:
    now = time.time()
    lst = _free_trial_log[ip]
    # purge older than 24h
    cutoff = now - 86400
    _free_trial_log[ip] = [t for t in lst if t > cutoff]
    lst = _free_trial_log[ip]
    if len(lst) >= FREE_TRIAL_PER_DAY:
        return False, f"free_trial quota {FREE_TRIAL_PER_DAY}/day exceeded for IP {ip}. Pay $5 USDC via payment-signature."
    return True, ""

def _record_free_trial(ip: str):
    _free_trial_log[ip].append(time.time())

@app.get("/health")
def health():
    return {"status":"ok","service":"aegis-sentinel","x402_rail":"0xDC056FcF4d3442110862E7eA7c02b5E81eAD4B1F Base","version":"2.1-hardened","security":{"rate_limit":f"{RATE_LIMIT_PER_MIN}/min per IP","free_trial":f"{FREE_TRIAL_PER_DAY}/day per IP","max_code":"200KB","replay_ttl":"1h","chains":sorted(list(ALLOWED_CHAINS))}}

@app.post("/api/v1/aegis-scan")
async def aegis_scan(request: Request, payment_signature: Optional[str]=Header(None, alias="payment-signature")):
    ip = _client_ip(request)
    limited, reason = _is_rate_limited(ip)
    if limited:
        return JSONResponse(status_code=429, content={"status":429,"error":"Too Many Requests","reason":reason,"ip":ip})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"status":400,"error":"Invalid JSON body"})
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"status":400,"error":"Body must be JSON object"})
    code = body.get("code", "")
    chain = body.get("chain", "base")
    free_trial = body.get("free_trial", False)
    # input validation
    if chain.lower() not in ALLOWED_CHAINS:
        return JSONResponse(status_code=400, content={"status":400,"error":f"Unsupported chain {chain}. Allowed: {sorted(ALLOWED_CHAINS)}"})
    if code and len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return JSONResponse(status_code=413, content={"status":413,"error":f"Code too large {len(code.encode('utf-8'))} > {MAX_CODE_BYTES} bytes"})
    # free_trial quota check (only when requesting free)
    if free_trial:
        ok, msg = _free_trial_allowed(ip)
        if not ok:
            return JSONResponse(status_code=429, content={"status":429,"error":"free_trial quota exceeded","message":msg,"payment":{"amount":"5","token":"USDC","recipient":"0xDC056FcF4d3442110862E7eA7c02b5E81eAD4B1F","usdc_token":"0x036CbD53842c5426634e792a1dCF7187fB630A81","chain":"eip155:8453"}})
    # build headers dict case-insensitive
    headers = {}
    for k, v in request.headers.items():
        headers[k.lower()] = v
    # also include explicit payment_signature param
    if payment_signature:
        headers["payment-signature"] = payment_signature
    from agents.nevermined_skill import NeverminedSkillWrapper
    w = NeverminedSkillWrapper()
    result = w.handle_scan_request(body, headers=headers)
    # record free_trial success only on 200
    if free_trial and result.get("status") == 200:
        _record_free_trial(ip)
    # add security headers to response
    status = result.get("status", 200)
    # FastAPI will JSON serialize; we return JSONResponse to preserve status code for 402/429
    if status != 200:
        return JSONResponse(status_code=status, content=result)
    # add request id
    result["_meta"] = {"ip": ip, "request_id": hashlib.sha256(f"{ip}:{time.time()}".encode()).hexdigest()[:12]}
    return JSONResponse(status_code=200, content=result)

@app.post("/api/v1/aegis-subscribe")
async def aegis_subscribe(request: Request, payment_signature: Optional[str]=Header(None, alias="payment-signature")):
    ip = _client_ip(request)
    limited, reason = _is_rate_limited(ip)
    if limited:
        return JSONResponse(status_code=429, content={"status":429,"error":"Too Many Requests","reason":reason})
    try:
        body = await request.json()
    except:
        body = {}
    headers = {}
    for k, v in request.headers.items():
        headers[k.lower()] = v
    if payment_signature:
        headers["payment-signature"] = payment_signature
    from agents.nevermined_skill import NeverminedSkillWrapper
    w = NeverminedSkillWrapper()
    result = w.handle_subscription(headers=headers, body=body)
    status = result.get("status", 200)
    if status != 200:
        return JSONResponse(status_code=status, content=result)
    result["_meta"] = {"ip": ip, "request_id": hashlib.sha256(f"{ip}:{time.time()}".encode()).hexdigest()[:12]}
    return JSONResponse(status_code=200, content=result)

@app.get("/api/v1/aegis-offer")
def offer():
    from agents.nevermined_skill import NeverminedSkillWrapper
    return NeverminedSkillWrapper().create_subscription_offer()

# reset for tests
def _reset_webhook_state():
    _req_log.clear()
    _free_trial_log.clear()
    _blocked_ips.clear()
    from agents.nevermined_skill import _reset_security_state
    _reset_security_state()
