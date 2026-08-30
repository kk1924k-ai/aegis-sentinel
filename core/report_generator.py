from .analyzer import AegisReport
import json, hashlib, datetime

def markdown_report(report: AegisReport) -> str:
    d=report.to_dict()
    lines=[f"# AEGIS Sentinel — Audit Report", f"**Contract:** `{d['contract']}` | **Chain:** {d['chain']} | **Score:** {d['score']}/100", f"**Hash:** `{d['hash'][:16]}...` | **Time:** {d['duration_ms']}ms", "", f"**Critical:** {d['critical']} | **High:** {d['high']} | **Medium:** {d['medium']} | **Total:** {d['vulns']}", "", "## Findings"]
    if not d["details"]:
        lines.append("✅ No high-risk patterns detected (automated scan).")
    else:
        for f in d["details"]:
            lines.append(f"- **{f['severity'].upper()}** `{f['pattern']}` at {f['loc']}: {f['desc']}")
            lines.append(f"  ```solidity\n  {f['snippet']}\n  ```")
    lines += ["", "> "+d["disclaimer"], "", f"_Generated {datetime.datetime.utcnow().isoformat()}Z_"]
    return "\n".join(lines)
