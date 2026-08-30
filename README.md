# AEGIS Sentinel — Phase 1
Narrow AI audit agent: reentrancy / access-control / flash-loan / oracle / unchecked-call + Z3 stub.

## Quick start
```
pip install -r requirements.txt
python -c "from core.analyzer import AegisAnalyzer; a=AegisAnalyzer(); print(a.analyze(open('tests/fixtures/VulnerableBank.sol').read()).to_json())"
```

## Nevermined via Koka Bot
`agents/nevermined_skill.py` uses Koka wallet as payment rail. Fill `config/nevermined.yaml` when Koka replies, mock works until then.

## Immunefi + Farcaster
Both run in mock mode Phase 1, switch to live with API keys.

## Dashboard
```python
from infra.dash_metrics import Dashboard
d=Dashboard(); d.record_scan("immunefi",85,5000,0.5); d.print()
```
