# 2. Histórico e Evolução do Projeto

> Reconstruído a partir do histórico de desenvolvimento. Onde a data exata não é conhecida, uso
> marcos relativos. Itens marcados `REQUER VALIDAÇÃO` devem ser confirmados no código/repositório.

## Linha do tempo (marcos)

### Marco 0 — Concepção / blueprint
- Requisito inicial: **wallboard de TV para SOC/Executivo** do Vision One, para a PRODESP.
- Documento de arquitetura inicial (`Arquitetura-Dashboard-VisionOne.md`) definindo tiers de coleta,
  cache Redis, TimescaleDB para histórico e frontend de TV.

### Marco 1 — Protótipo standalone (SUBSTITUÍDO)
- Primeira versão do frontend: HTML standalone (`trendai-soc-dashboard.html` / `dashboard-vision-one.html`)
  com **4 cenas auto-rotativas** e um coletor Python, suportando modos **DEMO / JSON / API**.
- **Status:** substituído pelo frontend integrado servido pelo backend. Mantido como referência.

### Marco 2 — Backend FastAPI + Redis + coletor em tiers (ATUAL)
- Backend FastAPI servindo API + dashboard na **mesma origem** (sem servidor de frontend separado,
  sem Vite/npm).
- Coletor com **APScheduler** e 3 tiers (T1 60s, T2 5min, T3 15min).
- Redis como cache quente e **pub/sub** para push por WebSocket.
- Cliente Vision One com auth Bearer, paginação `nextLink` e backoff em 429.

### Marco 3 — Ampliação da coleta (ATUAL)
- Do conjunto inicial (workbench + posture + eventos) para uma coleta ampla no T3:
  attack surface, vulnerabilidades, MITRE, threat trend, identidade, IOCs (suspicious objects,
  com resolução DNS + geolocalização) e inventário de endpoints.
- Introdução de **keep-last-good** (`_merge_keep`) para não zerar painéis (MITRE/identidade) em timeout.

### Marco 4 — Tenant PRODESP (ATUAL; substituiu TM-LAR)
- Tenant padrão migrou de **`TM-LAR`** (usado em guias antigos) para **`prodesp-sp`** (config atual).
- Descoberta operacional: licença **CREM-Core expirada** → endpoints `asrm/attackSurface*`,
  `asrm/highRisk*`, `asrm/internalAssetVulnerabilities` retornam **403**. Decisão: alimentar o
  dashboard por **`asrm/securityPosture`** (200), que traz os agregados necessários. Tratamento
  tolerante a 403 mantido (é sinal de venda de renovação, não erro do sistema).

### Marco 5 — Refino visual das 4 telas (MAIS RECENTE)
Sequência de correções de layout/renderização validadas em TV:
- **Gauge (Security Posture):** escala de cor invertida conforme o Vision One (0–30 verde/baixo,
  30–70 âmbar/médio, 70–100 vermelho/alto).
- **Dashboard:** rebalanceamento de grid; KPIs que dividem altura (flex) para não cortar; Risk Factors
  redesenhado de cards para **ranking de barras horizontais**; Vulnerability/Attack Surface ajustados.
- **Cyber:** projeção do mapa reescrita para **proporção real** (fim de distorção/corte), continentes
  preenchidos, **comets de IOC animados** convergindo para São Paulo, Top IOCs sem overflow.
- **Centro (SOC):**
  - **Threat Trends** trocou de contagem **total** de OAT (saturava em 100k → linha reta) para
    **detecções de alto risco** (`riskLevel eq 'high'`), com área em gradiente e pico destacado.
  - **MITRE:** as **14 táticas** passam a dividir a altura do painel (Exfiltration/Impact deixaram de cortar).
  - **Threat Detection:** `grid-auto-rows` para 2 linhas de KPIs estáveis (labels não cortam).
  - **Live Detections:** corrigido **corte vertical** (itens `flex:1` dividem a altura) e invasão de
    texto no timestamp (`minmax(0,1fr)` na coluna).

## Funcionalidades removidas / substituídas
- **Modos DEMO/JSON e dados sintéticos** (ex.: `feedItem()` com Mimikatz/Cobalt Strike hardcoded):
  legado do protótipo, **não usado** no fluxo atual (dados vêm da API real).
- **Frontend standalone** → substituído pelo servido via backend.
- **Tenant TM-LAR** → **prodesp-sp**.
- **Threat Trends por total OAT** → por **alto risco**.
- **Mapa equirretangular** → **projeção proporcional**.

## Estado por requisito
Ver a tabela de requisitos em `PROJECT_OVERVIEW.md` (§ Requisitos funcionais) e `ROADMAP.md`.
