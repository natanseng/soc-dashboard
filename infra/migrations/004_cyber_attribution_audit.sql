-- =====================================================================================
-- 004_cyber_attribution_audit.sql  |  Trilha de auditoria de (re)atribuicao (regra 4)
-- =====================================================================================
-- Toda (re)atribuicao registra: estado anterior, novo estado, metodo, confianca, mapeamento
-- e data. Sem FK para cyber_oat_observation (a auditoria sobrevive a retencao de 30h da obs).
-- Aditiva; aplicada via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- =====================================================================================
CREATE TABLE IF NOT EXISTS cyber_attribution_audit (
    audit_id                 bigserial   PRIMARY KEY,
    observation_id           bigint      NOT NULL,          -- ref. logica (sem FK; sobrevive a retencao)
    tenant_id                text        NOT NULL REFERENCES tenant(tenant_id),
    previous_organization_id text,
    previous_status          text,
    previous_method          text,
    previous_confidence      text,
    new_organization_id      text,
    new_status               text        NOT NULL,
    new_method               text,
    new_confidence           text,
    mapping_id               bigint,                        -- mapeamento que gerou a atribuicao (se houver)
    mapping_type             text,
    reason                   text        NOT NULL,          -- reattribution | collection | manual | ...
    changed_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_attr_audit_obs    ON cyber_attribution_audit (observation_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS ix_attr_audit_tenant ON cyber_attribution_audit (tenant_id, changed_at DESC);

-- =====================================================================================
-- ROLLBACK:
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_attribution_audit CASCADE;
-- DELETE FROM schema_migrations WHERE version='004_cyber_attribution_audit';
-- COMMIT;
-- =====================================================================================
