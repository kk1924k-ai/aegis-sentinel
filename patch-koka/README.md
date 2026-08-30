# Patch Koka — 3-й скилл $299
Применить в репо nevermined-koka-bot:
1. server.js — вставить блок из server.js.patch после app.post('/api/v1/aegis-scan'...)
2. .well-known/agent.json — добавить объект из agent.json.patch в массив skills
3. commit + push -> Render автодеплой, проверить: curl https://nevermined-koka-bot.onrender.com/api/v1/aegis-subscribe -X POST -d '{}' -> 402 payment_required amount 299
