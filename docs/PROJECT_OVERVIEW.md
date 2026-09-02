# 1. Resumo Executivo

## Problema que o projeto resolve
Equipes de SOC e liderança da **PRODESP** precisam de uma visão **contínua, em tela de TV**, do
estado de segurança do ambiente monitorado pelo **Trend Vision One**. O console nativo do Vision One
não é adequado para exibição 24/7 em wallboard (excesso de navegação, densidade, não é "à distância").
Este projeto entrega um painel próprio, legível de longe, que rotaciona entre visões executiva e
operacional e se atualiza em tempo real.

## Usuários
- **Analistas de SOC** (operação): telas de detecção, MITRE ATT&CK, live feed, mapa de ameaças.
- **Liderança / executivos** (PRODESP e Trend Micro): postura de risco, superfície de ataque,
  vulnerabilidades, adoção, identidade.
- **Operador do dashboard** (CS técnico Trend Micro): mantém e opera o ambiente.

## Objetivos principais
1. Exibir, sem interação, o panorama de segurança do tenant em uma TV.
2. Atualização "ao vivo" (segundos a minutos) sem recarregar a página.
3. Legibilidade de wallboard: números grandes, cores por severidade, sem cortes/sobreposição.
4. Resiliência: uma falha de coleta isolada não derruba o painel.
5. Multi-tenant por design (chaves e rotas por `tenant`), embora hoje só a PRODESP esteja ativa.

## Funcionalidades já existentes (implementadas)
- **4 telas rotativas** (20s, navegáveis por seta/espaço, tela cheia F11):
  - **Dashboard (executiva):** Security Posture (Risk Index em gauge), Threat Overview, Workbench,
    Attack Surface, Vulnerability Management, Risk Factors.
  - **Centro (SOC):** Threat Detection (KPIs), MITRE ATT&CK (14 táticas), Live Detections,
    Threat Trends (alto risco, 24h), Endpoint Security, Identity Security.
  - **Cyber:** mapa de ameaças animado (projeção real, comets de IOC até São Paulo), Top IOCs, atacantes.
  - **Adoção:** adoção de recursos endpoint × servidor, saúde, valor/ROI.
- **Coletor em tiers** (60s / 5min / 15min) contra a API Vision One v3.0.
- **Cache Redis** + **push por WebSocket** (deltas em tempo real).
- **Dashboard servido pelo próprio backend** (mesma origem, sem CORS/servidor separado).
- **Mapa geo opcional** (GeoLite2), desativável.

## Estado atual
Operacional e em uso para exibição em TV, rodando contra o tenant real **prodesp-sp**. As 4 telas
foram revisadas e validadas em tela. Persistência histórica (TimescaleDB) **provisionada mas não
integrada** (o código só usa Redis). Sem suíte de testes automatizados. Deploy manual (WSL2) com
atalhos `.bat` para Windows.

## Principais componentes da solução
| Componente | Papel |
|---|---|
| `collectors/run.py` | Scheduler (APScheduler) que dispara os tiers e grava no Redis + pub/sub |
| `collectors/tiers.py` | Todas as coletas e parsing da API Vision One |
| `app/main.py` | API FastAPI (overview + WebSocket) e serve o dashboard |
| `app/vision_one.py` | Cliente HTTP da Vision One (auth, paginação, retry 429) |
| `app/cache.py` / Redis | Cache quente + canal pub/sub |
| `app/geo.py` / GeoLite2 | Geolocalização de IOCs para o mapa (opcional) |
| `static/index.html` | Frontend single-file (ECharts, 4 telas) |
| `infra/` (Docker) | Redis + TimescaleDB |

## Requisitos funcionais (visão; detalhamento em BACKEND/FRONTEND/BUSINESS_RULES)
- RF01 Postura de segurança (Risk Index + níveis exposição/ataque/config) — **implementado** (securityPosture).
- RF02 Contadores de Workbench por severidade/status — **implementado**.
- RF03 Eventos OAT (24h/7d/30d + variação) — **implementado**.
- RF04 MITRE ATT&CK por tática (14) — **implementado** (satura em 100k em táticas de alto volume).
- RF05 Live feed de detecções — **implementado**.
- RF06 Threat Trends (série 24h de alto risco) — **implementado**.
- RF07 Endpoint Security (total, EDR conn/disc, EPP off, desatualizados, OS/tipo) — **implementado**.
- RF08 Identity Security (brute force, contas válidas, cred dumping, priv esc) — **implementado**.
- RF09 Attack Surface (IPs públicos, portas, hosts inseguros, cloud, contas fracas) — **parcial/tolerante**
  (via securityPosture; endpoints ASRM diretos em 403).
- RF10 Vulnerabilidades (CVEs, MTTP, dias sem patch, cobertura) — **implementado** (via securityPosture).
- RF11 Adoção de recursos endpoint × servidor — **implementado**.
- RF12 Mapa de ameaças geolocalizado + Top IOCs — **implementado** (depende de GeoLite2; senão inativo).
- RF13 Persistência histórica / tendências de longo prazo — **planejado** (schema pronto, sem integração).
