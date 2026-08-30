"""Fetch.ai uAgent — AEGIS Sentinel security-audit capability (HARDENED v2.1)
Almanac: capability security-audit, pay-per-call via FET or free via AEGIS x402 bridge
Requires: pip install uagents  (бесплатно, open-source)
"""
try:
    from uagents import Agent, Context, Model
    HAS_UAGENTS = True
except ImportError:
    HAS_UAGENTS = False
    Agent = Context = Model = object

from typing import Optional

class ScanRequest(Model if HAS_UAGENTS else object):
    code: str
    filename: str = "Contract.sol"
    chain: str = "base"

class ScanResponse(Model if HAS_UAGENTS else object):
    score: int
    vulns: int
    critical: int
    hash: str
    details: str

if HAS_UAGENTS:
    aegis_agent = Agent(
        name="aegis-sentinel",
        seed="aegis_sentinel_fetch_seed_phase2_hardened",
        port=8001,
        endpoint=["http://localhost:8001/submit"],
    )

    @aegis_agent.on_event("startup")
    async def startup(ctx: Context):
        # fixed: use agent address directly, not ctx.address
        addr = str(aegis_agent.address) if hasattr(aegis_agent, "address") else "unknown"
        ctx.logger.info(f"AEGIS uAgent started: {addr} — capability security-audit, x402 rail 0xDC05... Base")

    # keep on_query for compat (warning ok) + also support on_rest if available
    try:
        @aegis_agent.on_query(model=ScanRequest, replies={ScanResponse})
        async def handle_scan(ctx: Context, sender: str, msg: ScanRequest):
            from core.analyzer import AegisAnalyzer
            a = AegisAnalyzer()
            r = a.analyze(msg.code, msg.filename, msg.chain)
            d = r.to_dict()
            await ctx.send(sender, ScanResponse(score=d["score"], vulns=d["vulns"], critical=d["critical"], hash=d["hash"], details=str(d["details"][:2])))
    except Exception as e:
        print(f"[FETCH] on_query not available: {e}")

else:
    aegis_agent = None
    print("[FETCH] uagents not installed — run: pip install uagents. Stub mode, Almanac not reachable.")

def get_almanac_registration():
    return {
        "name": "aegis-sentinel",
        "capability": "security-audit",
        "protocols": ["solidity-audit", "reentrancy-detection", "formal-verification"],
        "pricing": {"amount": 5, "token": "FET", "alt": "5 USDC via x402 Base 0xDC05..."},
        "endpoint": "http://localhost:8001/submit",
        "address": str(aegis_agent.address) if HAS_UAGENTS and aegis_agent else None,
        "status": "live" if HAS_UAGENTS else "stub-needs-uagents",
        "x402_bridge": "https://nevermined-koka-bot.onrender.com/api/v1/aegis-scan",
        "note": "Бесплатно — uagents open-source, без подписок. Агент зарабатывает через x402.",
    }

if __name__ == "__main__":
    if HAS_UAGENTS:
        aegis_agent.run()
    else:
        import json
        print(json.dumps(get_almanac_registration(), indent=2, ensure_ascii=False))
