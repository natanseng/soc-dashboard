-- =====================================================================================
-- 005_cyber_workbench_alert.sql  |  Inventario de workbenches (tela "Alertas")
-- =====================================================================================
-- Registro COMPLETO de cada workbench por tenant (1 linha por (tenant, alert_id)), distinto
-- do cyber_workbench_indicator (que so guarda indicadores externos). Base para: consolidado
-- por Model Severity, por status, historico 30d, distribuicao por tenant, correlacao por
-- suborgao (via instancia) e MTTD/MTTR (regras do projeto vision-one-soc-dashboard).
-- Dedup por (tenant, alert_id) + upsert dos campos mutaveis (status muda apos criacao).
-- Aditiva; aplicada via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- =====================================================================================
CREATE TABLE IF NOT EXISTS cyber_workbench_alert (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    alert_id              text        NOT NULL,              -- WB-...
    severity              text,                              -- Model Severity (dinamico: critical/high/medium/low/...)
    status                text,                              -- Open | In Progress | Closed
    investigation_status  text,                              -- New | In Progress | True Positive | False Positive | ...
    investigation_result  text,
    model                 text,                              -- nome do modelo de deteccao
    model_id              text,
    model_type            text,                              -- preset (nativo) | custom
    alert_provider        text,                              -- SAE | TI
    score                 integer,
    created_at            timestamptz NOT NULL,              -- createdDateTime (ancora de criacao / janela 30d)
    updated_at_v1         timestamptz,                       -- updatedDateTime (ancora de resolucao p/ Closed)
    matched_first         timestamptz,                       -- MENOR matchedDateTime (OAT) -> MTTD preset
    matched_last          timestamptz,                       -- MAIOR matchedDateTime (OAT) -> MTTD custom
    oat_count             integer     NOT NULL DEFAULT 0,    -- nº de matchedDateTime encontrados (matchedRules/filters/events)
    detect_seconds        double precision,                  -- MTTD EFETIVO (preset=first, custom=last); NULL se sem OAT ou delta<0
    resolve_seconds       double precision,                  -- MTTR (updated-created) SOMENTE Closed; NULL caso contrario ou delta<0
    -- atribuicao a suborgao via instancia (managementScopeInstanceId) — reusa cyber_attribution
    organization_id                     text,
    organization_attribution_status     text NOT NULL DEFAULT 'unassigned',
    organization_attribution_method     text NOT NULL DEFAULT 'unknown',
    organization_attribution_confidence text NOT NULL DEFAULT 'unavailable',
    organization_attribution_evidence   text,
    attribution_identifiers             jsonb,               -- so o necessario (managementScopeInstanceId/GroupId)
    workbench_link        text,
    first_collected_at    timestamptz NOT NULL DEFAULT now(),
    last_collected_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_cyber_workbench_alert PRIMARY KEY (tenant_id, alert_id),
    -- org atribuido DEVE pertencer ao mesmo tenant (MATCH SIMPLE -> nao checa quando org NULL)
    CONSTRAINT fk_wba_tenant_org FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organization (tenant_id, organization_id),
    CONSTRAINT ck_wba_attr_status CHECK (organization_attribution_status IN
        ('attributed','ambiguous','unassigned','unavailable')),
    CONSTRAINT ck_wba_attr_coherence CHECK (
        (organization_attribution_status = 'attributed' AND organization_id IS NOT NULL)
     OR (organization_attribution_status IN ('unassigned','ambiguous','unavailable') AND organization_id IS NULL)),
    CONSTRAINT ck_wba_detect_nonneg  CHECK (detect_seconds  IS NULL OR detect_seconds  >= 0),
    CONSTRAINT ck_wba_resolve_nonneg CHECK (resolve_seconds IS NULL OR resolve_seconds >= 0)
);
CREATE INDEX IF NOT EXISTS ix_wba_tenant_created ON cyber_workbench_alert (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_wba_tenant_status  ON cyber_workbench_alert (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_wba_tenant_org     ON cyber_workbench_alert (tenant_id, organization_id);
CREATE INDEX IF NOT EXISTS ix_wba_tenant_sev     ON cyber_workbench_alert (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_wba_tenant_type    ON cyber_workbench_alert (tenant_id, model_type);

-- =====================================================================================
-- ROLLBACK:
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_workbench_alert CASCADE;
-- DELETE FROM schema_migrations WHERE version='005_cyber_workbench_alert';
-- COMMIT;
-- =====================================================================================
