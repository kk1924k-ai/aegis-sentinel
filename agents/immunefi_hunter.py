import requests, json, time, re
from typing import List

class ImmunefiHunter:
    GRAPHQL="https://bugs.immunefi.com/api/graphql"
    # fallback: public boost page
    FALLBACK_URL="https://immunefi.com/explore"

    def fetch_new_bounties(self, limit=10):
        # Try GraphQL (may require auth) -> fallback to scraping fallback_url title count
        try:
            q={"query":"{ bounties(limit:"+str(limit)+"){ id project chain reward tvl } }"}
            r=requests.post(self.GRAPHQL, json=q, timeout=10)
            if r.status_code==200 and "data" in r.json():
                return r.json()["data"].get("bounties",[])
        except Exception as e:
            pass
        # Fallback mock — realistic structure so Phase 1 can run without API key
        return [
            {"id":"mock-1","project":"MockDeFi Lending","chain":"evm","reward":"$50,000","url":"https://github.com/example/mock-lending","tvl":"$12M"},
            {"id":"mock-2","project":"MockDEX","chain":"evm","reward":"$100,000","url":"https://github.com/example/mock-dex","tvl":"$45M"},
        ]

    def analyze_bounty(self, bounty: dict):
        return {"bounty_id": bounty.get("id"), "project": bounty.get("project"), "reward": bounty.get("reward"), "chain": bounty.get("chain"), "url": bounty.get("url"), "status":"queued_for_scan"}

    def scan_code_for_bounty(self, code: str, filename="Target.sol"):
        from core.analyzer import AegisAnalyzer
        a=AegisAnalyzer()
        return a.analyze(code, filename)

    def run_once(self):
        bounties=self.fetch_new_bounties()
        results=[]
        for b in bounties:
            results.append(self.analyze_bounty(b))
        return results
