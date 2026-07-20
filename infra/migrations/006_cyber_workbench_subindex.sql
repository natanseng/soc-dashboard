-- =====================================================================================
-- 006_cyber_workbench_subindex.sql  |  Correlacao workbench -> subindice via coletor de origem
-- =====================================================================================
-- O subindice de um workbench (tela Alertas) e derivado do COLETOR de origem do OAT
-- (indicators[].field='collectorId' no payload do workbench). Um mapa coletor->subindice
-- (cyber_subindex_collector, dados de ambiente via seed) resolve o subindice; workbenches do
-- tenant de subindices sem coletor mapeado caem no default_subindex do tenant (nativos).
-- Aditiva; aplicada via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- =====================================================================================

-- subindice resolvido, gravado por-workbench (NULL = sem subindice / tenant sem subindices)
ALTER TABLE cyber_workbench_alert ADD COLUMN IF NOT EXISTS subindex text;
ALTER TABLE cyber_workbench_alert ADD COLUMN IF NOT EXISTS subindex_method text;  -- collector | default | none
CREATE INDEX IF NOT EXISTS ix_wba_tenant_subindex ON cyber_workbench_alert (tenant_id, subindex);

-- default de subindice por tenant (para os workbenches sem coletor mapeado; ex.: sggd -> 'SGGD')
ALTER TABLE cyber_tenant_config ADD COLUMN IF NOT EXISTS default_subindex text;

-- mapa coletor -> subindice (dados de ambiente; populado por seed). subindex casa com o NOME do
-- asset group (Cyber Risk Subindex) do tenant.
CREATE TABLE IF NOT EXISTS cyber_subindex_collector (
    tenant_id      text        NOT NULL REFERENCES tenant(tenant_id),
    collector_id   text        NOT NULL,
    collector_name text,
    subindex       text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_cyber_subindex_collector PRIMARY KEY (tenant_id, collector_id)
);
CREATE INDEX IF NOT EXISTS ix_subcol_tenant ON cyber_subindex_collector (tenant_id, subindex);

-- =====================================================================================
-- ROLLBACK:
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_subindex_collector CASCADE;
-- ALTER TABLE cyber_tenant_config DROP COLUMN IF EXISTS default_subindex;
-- ALTER TABLE cyber_workbench_alert DROP COLUMN IF EXISTS subindex;
-- ALTER TABLE cyber_workbench_alert DROP COLUMN IF EXISTS subindex_method;
-- DELETE FROM schema_migrations WHERE version='006_cyber_workbench_subindex';
-- COMMIT;
-- =====================================================================================
