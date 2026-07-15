# 20. Roadmap

Sugestões priorizadas, derivadas da dívida técnica e das limitações atuais. Ordem é recomendação, não compromisso.

## Curto prazo (semanas)
- **Proteger o acesso à porta 8000** (rede segregada / VPN / proxy reverso com auth) + **TLS/`wss`**. *(SECURITY/DEPLOYMENT)*
- **Empacotar as fontes localmente** (remover dependência de CDN na TV).
- **Versionar em Git** (rollback confiável) e registrar a **versão do ECharts**.
- **Testes de unidade dos parsers/regras** (`parse_posture`, `delta24h`, feed, `_count`/100k, `_merge_keep`). *(TESTING)*
- **Decidir sobre `map:attackers`** (remover leitura morta ou implementar alimentador).

## Médio prazo (1–2 meses)
- **Integrar o TimescaleDB**: o coletor passa a persistir `posture_snapshot` (por tick T1) e
  `sec_event`/`wb_alert`/`vulnerability`/`attack_geo`. Habilita **tendências reais** (7d/30d/YoY) em vez de
  contagens pontuais, e gráficos históricos por período. *(DATABASE §"fase futura")*
- **Observabilidade**: métricas do coletor (sucesso/falha por tier, latência), readiness real, alerta quando um tier fica indisponível.
- **Multi-tenant**: parametrizar `TENANT_LABELS`/tema; validar/allowlist de `tenant`; seleção de tenant.
- **Orquestrar o coletor** como serviço (systemd/container) junto da API.

## Longo prazo
- **Renovar CREM-Core** (decisão comercial/AM) para habilitar o **drill-down ASRM** (attack surface, high-risk,
  internal vulnerabilities por ativo) — hoje 403. É também **gancho de renovação** para a AM Karen Sea.
- **Alertas/limiares visuais** no wallboard (piscar/realçar quando métrica cruza um limite).
- **Exportação/relatórios** (snapshot PDF/PNG das telas) para reuniões executivas.
- **Modularizar o frontend** (build/bundler) caso a complexidade cresça além do single-file.
- **Substituir a sparkline decorativa** por série real.

## Dependências externas
- **CREM-Core** (comercial) → drill-down ASRM.
- **Rede corporativa** → egress p/ `api.xdr.trendmicro.com`, TLS no proxy, política de fontes offline.
