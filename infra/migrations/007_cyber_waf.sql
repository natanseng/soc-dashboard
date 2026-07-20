-- =====================================================================================
-- 007_cyber_waf.sql  |  Indicador "Bloqueios WAF" (tela Cyber)
-- =====================================================================================
-- Workbenches gerados por deteccoes de coletores WAF (ex.: Imperva). O collectorId de origem
-- (indicators[].field='collectorId') e classificado como WAF via cyber_waf_collector (seed).
-- A URL atacada vem de indicators[].field='requests'; guardamos o HOST encurtado (sem www/path).
-- Aditiva; aplicada via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- =====================================================================================
ALTER TABLE cyber_workbench_alert ADD COLUMN IF NOT EXISTS waf_collector text;   -- collectorId WAF de origem (NULL = nao-WAF)
ALTER TABLE cyber_workbench_alert ADD COLUMN IF NOT EXISTS waf_url_host  text;    -- host atacado (encurtado) do campo requests
CREATE INDEX IF NOT EXISTS ix_wba_waf      ON cyber_workbench_alert (waf_collector) WHERE waf_collector IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_wba_waf_host ON cyber_workbench_alert (waf_url_host)  WHERE waf_url_host  IS NOT NULL;

-- coletores classificados como WAF (dados de ambiente; populado por seed)
CREATE TABLE IF NOT EXISTS cyber_waf_collector (
    tenant_id      text        NOT NULL REFERENCES tenant(tenant_id),
    collector_id   text        NOT NULL,
    collector_name text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_cyber_waf_collector PRIMARY KEY (tenant_id, collector_id)
);

-- =====================================================================================
-- ROLLBACK:
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_waf_collector CASCADE;
-- ALTER TABLE cyber_workbench_alert DROP COLUMN IF EXISTS waf_collector;
-- ALTER TABLE cyber_workbench_alert DROP COLUMN IF EXISTS waf_url_host;
-- DELETE FROM schema_migrations WHERE version='007_cyber_waf';
-- COMMIT;
-- =====================================================================================
