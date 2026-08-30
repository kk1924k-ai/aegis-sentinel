import json, time

class Dashboard:
    def __init__(self, path=None):
        self.path=path
        self.m={"total_scans":0,"total_earnings_usd":0.0,"gas_spent_usd":0.0,"false_positives":0,"avg_score":0,"scores":[],"subscriptions":{"active":0,"revenue":0.0,"churn":0},"platforms":{"nevermined":{"scans":0,"revenue":0.0},"immunefi":{"scans":0,"revenue":0.0},"farcaster":{"scans":0,"revenue":0.0},"fetch_ai":{"scans":0,"revenue":0.0}}}

    def record_scan(self, platform, score, revenue=0.0, gas_cost=0.0):
        self.m["total_scans"]+=1
        self.m["total_earnings_usd"]+=revenue
        self.m["gas_spent_usd"]+=gas_cost
        self.m["scores"].append(score)
        self.m["avg_score"]=sum(self.m["scores"])/len(self.m["scores"]) if self.m["scores"] else 0
        if platform in self.m["platforms"]:
            self.m["platforms"][platform]["scans"]+=1
            self.m["platforms"][platform]["revenue"]+=revenue
        if self.path:
            with open(self.path,"w",encoding="utf-8") as f: json.dump(self.m,f,indent=2)

    def record_subscription(self, amount=299.0):
        self.m["subscriptions"]["active"]+=1
        self.m["subscriptions"]["revenue"]+=amount
        self.m["total_earnings_usd"]+=amount

    def render(self):
        m=self.m
        lines=["="*58,"       AEGIS SENTINEL — DASHBOARD  (Phase 2)","="*58,f"  Total Scans:      {m['total_scans']}",f"  Earnings:         ${m['total_earnings_usd']:.2f}",f"  Gas Spent:        ${m['gas_spent_usd']:.2f}",f"  Net Profit:       ${m['total_earnings_usd']-m['gas_spent_usd']:.2f}",f"  Avg Score:        {m['avg_score']:.1f}/100",f"  Subscriptions:    {m['subscriptions']['active']} active | ${m['subscriptions']['revenue']:.2f} MRR | churn {m['subscriptions']['churn']}","-"*58]
        for p,d in m["platforms"].items():
            lines.append(f"  {p:15s} | scans {d['scans']:4d} | rev ${d['revenue']:.2f}")
        lines.append("="*58)
        return "\n".join(lines)
    def print(self):
        print(self.render())
