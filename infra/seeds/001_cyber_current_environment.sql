-- =====================================================================================
-- 001_cyber_current_environment.sql  |  SEED (dados do ambiente atual) — NAO e schema
-- =====================================================================================
-- Popula o cadastro dinamico com os orgaos/tenants HOJE existentes no ambiente. Idempotente
-- (ON CONFLICT DO NOTHING). Reutiliza a tabela base `tenant` (estrutura do init.sql:
-- tenant_id, display_name, region_base) — traz para o registro os tenants que ate agora so
-- existiam via .env (detran-sp, iamspe-sp, sggd). prodesp-sp ja existe (init.sql).
--
-- IMPORTANTE: NENHUM token/API key aqui. Segredos permanecem no .env, indexados por tenant_id.
-- O cadastro permanece DINAMICO: novos orgaos/tenants entram por novas linhas de seed
-- (ou pela UI/admin), sem alterar o schema.
--
-- Aplicacao (separada da migration; nao passa pelo runner de schema):
--   PSQL="docker exec -i infra-db-1 psql -U socdash -d socdash" ; \
--   cat infra/seeds/001_cyber_current_environment.sql | $PSQL -v ON_ERROR_STOP=1
-- =====================================================================================

-- 1) Orgaos (ordem de exibicao conforme dashboard)
INSERT INTO organization (organization_id, name, display_order) VALUES
    ('org-prodesp', 'Prodesp', 1),
    ('org-detran',  'Detran',  2),
    ('org-iamspe',  'Iamspe',  3),
    ('org-sggd',    'SGGD',    4)
ON CONFLICT (organization_id) DO NOTHING;

-- 2) Tenants no cadastro BASE `tenant` (reuso da estrutura existente). Autossuficiente:
--    inclui prodesp-sp (ja criado pelo init.sql) com ON CONFLICT DO NOTHING = no-op no socdash.
INSERT INTO tenant (tenant_id, display_name) VALUES
    ('prodesp-sp', 'Prodesp'),
    ('detran-sp',  'Detran'),
    ('iamspe-sp',  'Iamspe'),
    ('sggd',       'SGGD')
ON CONFLICT (tenant_id) DO NOTHING;

-- 3) Configuracao Cyber por tenant (vinculo org + flags). 1:1 com `tenant`.
INSERT INTO cyber_tenant_config
    (tenant_id, organization_id, cyber_enabled, oat_enabled, workbench_enabled, suspicious_objects_enabled) VALUES
    ('prodesp-sp', 'org-prodesp', true, true, true, true),
    ('detran-sp',  'org-detran',  true, true, true, true),
    ('iamspe-sp',  'org-iamspe',  true, true, true, true),
    ('sggd',       'org-sggd',    true, true, true, true)
ON CONFLICT (tenant_id) DO NOTHING;
