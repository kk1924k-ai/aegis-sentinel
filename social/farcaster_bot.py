import requests, json, time

class FarcasterBountyBot:
    def __init__(self, config: dict):
        self.signer_uuid=config.get("farcaster_signer_uuid","mock")
        self.api_key=config.get("neynar_api_key","mock")
        self.hub_url=config.get("hub_url","https://api.neynar.com")
        self.is_mock=self.api_key=="mock"

    def search_bounties(self, keywords=None):
        keywords=keywords or ["bounty","audit","solidity review"]
        if self.is_mock:
            return [{"hash":"0xmock1","text":"Need audit for ERC20 staking — bounty $500 #audit","author":"degen.eth"},{"hash":"0xmock2","text":"Solidity review needed for lending pool #solidity","author":"builder.lens"}]
        # real: Neynar search — kept minimal
        results=[]
        for kw in keywords:
            try:
                r=requests.get(f"{self.hub_url}/v2/farcaster/cast/search", params={"q":kw,"limit":5}, headers={"api_key": self.api_key}, timeout=8)
                if r.status_code==200:
                    results.extend(r.json().get("result",{}).get("casts",[]))
            except: pass
        return results

    def format_reply(self, scan_result: dict):
        score=scan_result.get("score",0)
        vulns=scan_result.get("vulns",0)
        emoji="✅" if score>=90 else "⚠️" if score>=70 else "🚨"
        return f"{emoji} AEGIS Express Scan\nScore: {score}/100\nVulns: {vulns}\nHash: {scan_result.get('hash','')[:16]}...\nFull report via Nevermined pay-per-scan ($5 USDC)\n_Disclaimer: Automated scan, not a human audit._"

    def respond_with_scan(self, cast_hash: str, scan_result: dict):
        text=self.format_reply(scan_result)
        print(f"[FARCASTER]{' (MOCK)' if self.is_mock else ''} Reply to {cast_hash}:\n{text}")
        return text
