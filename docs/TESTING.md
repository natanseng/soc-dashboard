# 13. Testes

## Estado atual (honesto)
**Não há suíte de testes automatizados** (sem `pytest`, sem CI). A validação é **manual e empírica**,
condicionada por uma restrição importante:

> A **API real da Vision One não é acessível** do ambiente de desenvolvimento assistido; as chamadas são
> validadas pelo CSTA no ambiente dele (via `curl`/logs). Por isso os coletores são **defensivos**
> (best-effort, `try/except`, timeouts, keep-last-good) — o comportamento sob falha é parte do design.

## Como mudanças são validadas hoje
- **Sintaxe JS:** `node --check` sobre o maior `<script>` extraído do `index.html`.
- **Sintaxe/So Python:** `python -m py_compile` nos arquivos alterados.
- **Fumaça de API:** `curl /healthz` (espera `redis:true`) e `curl /api/prodesp-sp/overview`.
- **Coletor:** observar os logs por tier (`T1 ... OK` / `WARNING ... indisponível: HTTP ...`).
- **Visual:** abrir na TV, checar cada tela (F para fullscreen, setas para navegar), verificar cortes/valores.
- **Redis:** `redis-cli KEYS/TTL/HGETALL` para confirmar que o tier gravou.

## Scripts de diagnóstico existentes (read-only)
- **`validate_tenant.py`** — valida token/tenant e conectividade básica com a Vision One.
- (Há também scripts pontuais de investigação criados ao longo do projeto; não fazem parte de uma suíte.)

## Recomendações (o que automatizar)
Priorizar **testes de unidade dos parsers e regras** (não dependem da rede):
- `parse_posture()` — fixtures de `securityPosture` (com/sem CREM) → conferir achatamento e `None`s.
- `event_tallies` `delta24h` — incluir caso `e24h_prev == 0` (RN04).
- `detections_feed` — severidade pelo maior `riskLevel` entre `filters[]` (RN05); ordenação por data.
- `_count` — com/sem `totalCount`; **saturação em 100k** (RN02).
- `_merge_keep` — mantém valor anterior quando o novo é `None` (RN14).
- `suspicious_objects` — `byType/byRisk/byAction`, agrupamento por host, `byCountry`.
Ferramentas sugeridas: `pytest`, `respx`/`httpx.MockTransport` (mock da Vision One), `ruff` (lint),
`mypy` (tipos). **Fumaça:** subir uvicorn com Redis de teste e checar `/healthz` + `/overview`.
**CI (GitHub Actions):** rodar lint + unit em cada push. `REQUER VALIDAÇÃO` de repositório Git.

## Casos-chave a cobrir (regressões prováveis)
- Teto de 100k não deve "quebrar" gráficos (RN02/RN03).
- 403 do CREM deve degradar graciosamente (painéis via posture continuam) — RN CREM.
- Timeout de uma tática/técnica não zera o painel (keep-last-good).
- `tenant` inválido não deve permitir leitura de chaves arbitrárias (ver SECURITY.md).
