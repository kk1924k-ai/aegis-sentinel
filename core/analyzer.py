from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import hashlib, time, re, json

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class VulnerabilityPattern(Enum):
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan_attack"
    ACCESS_CONTROL = "access_control"
    OVERFLOW = "integer_overflow"
    UNCHECKED_CALL = "unchecked_call"
    ORACLE = "oracle_manipulation"
    CENTRALIZATION = "centralization_risk"

@dataclass
class Vulnerability:
    pattern: VulnerabilityPattern
    severity: Severity
    location: str
    description: str
    code_snippet: str
    smt_proof: Optional[str] = None

@dataclass
class AegisReport:
    contract_name: str
    chain: str
    score: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration_ms: int = 0
    report_hash: str = ""
    disclaimer: str = "Automated analysis, not a substitute for human audit. Use at own risk."

    def to_dict(self):
        return {
            "contract": self.contract_name,
            "chain": self.chain,
            "score": self.score,
            "vulns": len(self.vulnerabilities),
            "critical": sum(1 for v in self.vulnerabilities if v.severity==Severity.CRITICAL),
            "high": sum(1 for v in self.vulnerabilities if v.severity==Severity.HIGH),
            "medium": sum(1 for v in self.vulnerabilities if v.severity==Severity.MEDIUM),
            "hash": self.report_hash,
            "duration_ms": self.scan_duration_ms,
            "disclaimer": self.disclaimer,
            "details": [{"pattern": v.pattern.value, "severity": v.severity.value, "loc": v.location, "desc": v.description, "snippet": v.code_snippet[:120]} for v in self.vulnerabilities]
        }
    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

class AegisAnalyzer:
    def __init__(self):
        self.rules = {
            VulnerabilityPattern.REENTRANCY: self._check_reentrancy,
            VulnerabilityPattern.ACCESS_CONTROL: self._check_access_control,
            VulnerabilityPattern.FLASH_LOAN: self._check_flash_loan,
            VulnerabilityPattern.OVERFLOW: self._check_overflow,
            VulnerabilityPattern.UNCHECKED_CALL: self._check_unchecked,
            VulnerabilityPattern.ORACLE: self._check_oracle,
        }

    def _check_reentrancy(self, code, filename):
        vulns=[]
        lines=code.split("\n")
        for i,line in enumerate(lines):
            stripped=line.strip()
            if re.search(r"\.call\s*\{.*value", line) or re.search(r"\.call\s*\(", line):
                # skip if nonReentrant or checks-effects-interactions already done
                if "nonReentrant" in code:
                    continue
                # look ahead 5 lines for state write after call
                after="\n".join(lines[i+1:i+6])
                if re.search(r"balances\s*\[|balances\s*\(|_\s*=\s*0|balanceOf|state|totalSupply", after):
                    vulns.append(Vulnerability(VulnerabilityPattern.REENTRANCY, Severity.CRITICAL, f"{filename}:{i+1}", "External call before state update — reentrancy", stripped))
                elif "call" in line and "require" not in after and "balances" in code:
                    vulns.append(Vulnerability(VulnerabilityPattern.REENTRANCY, Severity.HIGH, f"{filename}:{i+1}", "Low-level call without Checks-Effects-Interactions pattern", stripped))
        return vulns

    def _check_access_control(self, code, filename):
        vulns=[]
        dangerous=["transferOwnership","setOwner","setFee","pause","unpause","upgradeTo","mint","burn","withdraw","drain","setOracle","setPrice"]
        lines=code.split("\n")
        for i,line in enumerate(lines):
            for fn in dangerous:
                if fn in line and "function" in line:
                    ctx="\n".join(lines[max(0,i):i+3])
                    if "onlyOwner" not in ctx and "onlyRole" not in ctx and "require(msg.sender" not in ctx and "if(msg.sender" not in ctx:
                        vulns.append(Vulnerability(VulnerabilityPattern.ACCESS_CONTROL, Severity.HIGH, f"{filename}:{i+1}", f"Function {fn} lacks access control", line.strip()))
        return vulns

    def _check_flash_loan(self, code, filename):
        vulns=[]
        if ("getReserves" in code or "getAmountsOut" in code) and "swap" in code.lower():
            if "balanceOf" in code or "reserve" in code.lower():
                vulns.append(Vulnerability(VulnerabilityPattern.FLASH_LOAN, Severity.HIGH, f"{filename}:global", "DEX price-sensitive logic — flash-loan manipulation vector", "swap + getReserves/balanceOf"))
        if "flashLoan" in code and "price" in code.lower():
            vulns.append(Vulnerability(VulnerabilityPattern.FLASH_LOAN, Severity.MEDIUM, f"{filename}:global", "Flash-loan callback with price logic", "flashLoan"))
        return vulns

    def _check_overflow(self, code, filename):
        vulns=[]
        m=re.search(r"pragma solidity \^?0\.(\d+)\.", code)
        is_old=False
        if m:
            minor=int(m.group(1))
            if minor < 8:
                is_old=True
        if is_old and "SafeMath" not in code:
            lines=code.split("\n")
            for i,line in enumerate(lines):
                if re.search(r"\+=|-=|\*=|\+|-|\*|/", line) and ("uint" in line or "balances" in line):
                    if "require" not in line and len(line.strip())>5:
                        vulns.append(Vulnerability(VulnerabilityPattern.OVERFLOW, Severity.MEDIUM, f"{filename}:{i+1}", "Arithmetic without SafeMath on Solidity <0.8", line.strip()))
                        break
        return vulns

    def _check_unchecked(self, code, filename):
        vulns=[]
        lines=code.split("\n")
        for i,line in enumerate(lines):
            if ".call(" in line or ".send(" in line or ".transfer(" in line:
                if "=" not in line.split("//")[0] and "require" not in line and "assert" not in line and "if" not in line:
                    # check next line not checking return
                    nxt="\n".join(lines[i:i+2])
                    if "require" not in nxt and "sent" not in nxt.lower():
                        vulns.append(Vulnerability(VulnerabilityPattern.UNCHECKED_CALL, Severity.MEDIUM, f"{filename}:{i+1}", "Unchecked low-level call return value", line.strip()))
        return vulns

    def _check_oracle(self, code, filename):
        vulns=[]
        if "oracle" in code.lower() and ("latestAnswer" in code or "getPrice" in code):
            if "stale" not in code.lower() and "heartbeat" not in code.lower() and "updatedAt" not in code:
                vulns.append(Vulnerability(VulnerabilityPattern.ORACLE, Severity.MEDIUM, f"{filename}:global", "Oracle price without staleness check", "oracle latestAnswer without updatedAt check"))
        return vulns

    def analyze(self, code: str, filename="Contract.sol", chain="evm") -> AegisReport:
        start=time.time()
        all_vulns=[]
        for pat, fn in self.rules.items():
            try:
                all_vulns.extend(fn(code, filename))
            except Exception as e:
                pass
        # dedupe by location+pattern
        seen=set()
        uniq=[]
        for v in all_vulns:
            k=(v.pattern.value, v.location)
            if k not in seen:
                seen.add(k)
                uniq.append(v)
        score=100
        for v in uniq:
            if v.severity==Severity.CRITICAL: score-=30
            elif v.severity==Severity.HIGH: score-=15
            elif v.severity==Severity.MEDIUM: score-=7
            elif v.severity==Severity.LOW: score-=2
        score=max(0, score)
        h=hashlib.sha256(f"{filename}:{score}:{len(uniq)}:{code[:200]}".encode()).hexdigest()
        elapsed=int((time.time()-start)*1000)
        return AegisReport(contract_name=filename, chain=chain, score=score, vulnerabilities=uniq, scan_duration_ms=elapsed, report_hash=h)
