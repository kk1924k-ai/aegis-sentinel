"""Gas Vault — Base ETH buffer for AEGIS, refill from Koka payout if needed"""
import time

class GasVault:
    def __init__(self, vault_wallet="0xDC056FcF4d3442110862E7eA7c02b5E81eAD4B1F", workers=None):
        self.vault=vault_wallet
        self.workers=workers or ["aegis-worker-1"]
        self.thresholds={"eth":0.01,"usdc":5.0}
        self.buffer_eth=0.05  # рекомендуемый буфер

    def check_balances(self):
        # stub — в проде через web3.py eth_getBalance на Base
        balances={w: {"eth":0.008,"usdc":12.0} for w in self.workers}
        balances[self.vault]={"eth":0.12,"usdc":120.0}
        return balances

    def auto_replenish(self):
        bals=self.check_balances()
        actions=[]
        for w,b in bals.items():
            if w==self.vault: continue
            if b["eth"] < self.thresholds["eth"]:
                need=self.thresholds["eth"]-b["eth"]+0.005
                actions.append(f"Replenish ETH {need:.4f} -> {w} from vault {self.vault} (Base)")
            if b["usdc"] < self.thresholds["usdc"]:
                actions.append(f"Replenish USDC -> {w}")
        if not actions:
            actions.append("All worker balances OK — no replenish needed")
        for a in actions: print(f"[VAULT] {a}")
        return actions

    def status(self):
        return {"vault": self.vault, "thresholds": self.thresholds, "buffer_eth": self.buffer_eth, "balances": self.check_balances()}
