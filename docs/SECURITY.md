# 17. Segurança

## Modelo de exposição (importante)
O dashboard é um **wallboard interno** (TV do SOC). Hoje **não há autenticação** no frontend nem na API:
qualquer host que alcance a porta **8000** consegue ler `GET /api/{tenant}/overview` e abrir o dashboard.
O `overview` expõe **dados sensíveis do cliente** (postura de segurança, CVEs, usuários/dispositivos de
maior risco, IOCs, geolocalização). Portanto, **a proteção depende da rede**, não da aplicação.

> **Prioridade nº 1:** restringir o acesso à porta 8000 (rede segregada / VPN / proxy reverso com
> autenticação). Ver DEPLOYMENT.md (produção proposta).

## Segredos
- **`V1_API_TOKEN`** (Bearer da Vision One) vive **apenas no `.env`** do backend, usado server-side pelo
  coletor. **Nunca** é enviado ao navegador (o front só fala com o backend próprio).
- `.env` **não deve ser versionado**; `.env.example` não contém valores reais.
- **Não logar o token.** Os logs do coletor mostram status/erros (`diag()`), não o header de auth.
- Rotacionar o token periodicamente (Administration → API Keys) e ao suspeitar de vazamento.

## CORS
`app/main.py` usa `allow_origins=["*"]` por conveniência de desenvolvimento. Em produção, servindo na
**mesma origem** atrás de proxy, isso é desnecessário — **restringir** (mesma origem) ou remover o middleware.

## Transporte (TLS)
- Dev: HTTP/`ws://` em `localhost` (aceitável na estação).
- Produção: **TLS obrigatório** no proxy (`https`/`wss`); o front deriva `wss` automaticamente quando servido em `https`.

## XSS / injeção
- **XSS:** dados externos (nome de host, valor de IOC, país/cidade) passam por `_esc()` antes de irem ao
  DOM (tooltips, feed, listas). Manter esse escape ao adicionar novos campos vindos da API.
- **Injeção de filtro:** os `TMV1-Filter`/`TMV1-Query` são montados com **valores fixos** no servidor
  (severidades, táticas, níveis) — **não** a partir de entrada do usuário. Sem superfície de injeção aqui.
- **`tenant` (query string):** usado como **chave Redis** e path da API. No front há `encodeURIComponent`.
  `REQUER VALIDAÇÃO`: garantir sanitização/allowlist de `tenant` no backend (evitar leitura de chaves arbitrárias).

## Dependências
- Versões fixadas em `requirements.txt` (pip). ECharts servido localmente (`REQUER VALIDAÇÃO` da versão).
- Recomendação: varredura periódica de vulnerabilidades (pip-audit) e atualização controlada.

## Rate limiting / abuso
- O backend **não** limita clientes; apenas trata **429 da Vision One** (backoff). Atrás de proxy com
  auth e rede restrita, o risco é baixo; se exposto, considerar rate limit no proxy.

## Recomendações priorizadas
1. **Restringir acesso à 8000** (rede/VPN/proxy com auth). — *alto*
2. **TLS** em produção (`wss` para o WebSocket). — *alto*
3. **Restringir CORS** (mesma origem). — *médio*
4. **Sanitizar/allowlist `tenant`** no backend. — *médio*
5. **Rotação de token** + política de segredo (não versionar `.env`). — *médio*
6. **pip-audit** periódico. — *baixo*
