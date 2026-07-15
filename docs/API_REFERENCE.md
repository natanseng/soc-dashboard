# API Reference

Backend próprio (FastAPI, `app/main.py`). Base local: `http://localhost:8000`.
Todos os dados vêm do Redis (populado pelo coletor); a API **não** chama a Vision One diretamente.

## `GET /healthz`
Liveness + status do Redis.
- **Resposta 200:** `{"status":"ok","redis":true}`
- **Degradado:** `{"status":"degraded","redis":false,"error":"<msg>"}` (não derruba o processo)
- **Arquivo:** `app/main.py::healthz`

## `GET /api/{tenant}/overview`
Snapshot completo consumido pelo dashboard no boot.
- **Path param:** `tenant` (ex.: `prodesp-sp`). Lê chaves `v1:{tenant}:*` do Redis.
- **Exemplo:** `curl http://localhost:8000/api/prodesp-sp/overview`
- **Resposta 200 (formato):**
```json
{
  "tenant": "prodesp-sp",
  "posture":  { "risk_index": 65, "exposure": "high", "attack": "medium", "config": "medium",
                "vuln": {...}, "surface": {...}, "factors": [...], "adoption": {...} },
  "workbench":{ "critical":"0","high":"325","medium":"...","low":"...",
                "open":"14","in_progress":"0","closed":"..." },
  "events":   { "e24h":"...","e24h_prev":"...","e7d":"...","e30d":"...","delta24h":"..." },
  "surface":  { "devices":"...","critical":"...","unmanaged":"...","cloud":"...","accounts":"..." },
  "vuln":     { "counts": {"high":..,"medium":..,"low":..}, "top": [...] },
  "mitre":    { "TA0043": 8, "TA0001": 100001, ... },
  "feed":     [ {"time":"...","host":"...","name":"...","sev":"high","tactic":"...","technique":"..."} ],
  "trend":    [ {"t":"...","n":76}, ... ],
  "identity": { "bruteForce":..,"validAccounts":..,"credDumping":..,"privEsc":.. },
  "ioc":      { "total":..,"byType":{..},"byRisk":{..},"byAction":{..},"high":..,"top":[..],"geo":[..],"byCountry":{..} },
  "endpoint": { "total":..,"edrConnected":..,"edrDisconnected":..,"eppOn":..,"eppOff":..,"outdated":..,
                "os":{"windows":..,"linux":..,"mac":..}, "type":{"server":..,"desktop":..} },
  "risk":     [ {"name":"...","score":..,"sub":"...","kind":"user|device"} ],
  "attackers":[ ["<membro>", <score>], ... ]
}
```
> **Notas:** `workbench`, `events` e `surface` vêm de **hashes** (valores string). `posture/vuln/mitre/feed/trend/identity/ioc/endpoint/risk` vêm de **JSON**. `attackers` vem de `ZREVRANGE v1:{tenant}:map:attackers 0..9 WITHSCORES` — **REQUER VALIDAÇÃO**: nenhum tier atual escreve nessa zset (provável legado; hoje o mapa é alimentado por `ioc.geo`).
- Chaves vazias retornam `{}`/`[]` (nunca erro) enquanto o coletor não populou.
- **Arquivo:** `app/main.py::overview`

## `WS /ws/{tenant}`
Deltas em tempo real. O servidor assina o canal Redis `ws:{tenant}` e retransmite cada mensagem publicada pelo coletor.
- **Mensagem:** texto JSON `{"type": "<recurso>", "data": <payload>}` onde `type` ∈
  `posture | workbench | events | mitre | feed | trend | identity | ioc | endpoint | risk | surface | vuln`.
- **Cliente:** reconecta em 5s ao fechar; roteia por `type` para `apply<Tipo>()` (ver FRONTEND.md).
- **Arquivo:** `app/main.py::ws`

## `GET /` (e estáticos)
Serve `backend/static/` (`html=True` → `index.html`). Montado **por último** para não sombrear as rotas de API.
- **Arquivo:** `app/main.py` (mount `StaticFiles`)

## CORS
`allow_origins=["*"]` (compatibilidade). Servindo na mesma origem, não é necessário — ver SECURITY.md.

## Endpoints Vision One consumidos (referência; detalhe em INTEGRATIONS.md)
`/v3.0/workbench/alerts`, `/v3.0/oat/detections`, `/v3.0/asrm/securityPosture`,
`/v3.0/asrm/highRiskUsers`, `/v3.0/asrm/highRiskDevices`, `/v3.0/asrm/attackSurfaceDevices`,
`/v3.0/asrm/attackSurfaceCloudAssets`, `/v3.0/asrm/attackSurfaceDomainAccounts`,
`/v3.0/asrm/internalAssetVulnerabilities`, `/v3.0/endpointSecurity/endpoints`,
`/v3.0/threatintel/suspiciousObjects`, `/v3.0/search/networkActivities` (reservado).
