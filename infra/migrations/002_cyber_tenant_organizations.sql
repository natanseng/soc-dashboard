-- =====================================================================================
-- 002_cyber_tenant_organizations.sql  |  Corrige a cardinalidade: Tenant 1 --- N Organizations
-- =====================================================================================
-- REGRA FUNDAMENTAL: o ambiente tem varios tenants; cada tenant contem 1..N orgaos.
-- A 001 (aplicada) modelava tenant->1 orgao (cyber_tenant_config.organization_id). Esta
-- migration corrige isso de forma ADITIVA, sem alterar a 001 e sem perda de dados:
--   * organization passa a PERTENCER a um tenant (organization.tenant_id + FK + UNIQUE composta);
--   * observacoes ganham atribuicao OPCIONAL de orgao (organization_id + status/method/confidence/
--     evidence) com FK composta (tenant_id, organization_id) -> organization (garante mesmo tenant);
--   * cyber_organization_mapping: mapeamentos dinamicos instancia/tag/id -> orgao;
--   * cyber_tenant_config.organization_id permanece LEGADO (removido na 003 apos backend validado).
-- Decisao (§1.4): NAO se cria cyber_organization_config; a config de orgao vive em `organization`
--   (cyber_enabled, attribution_enabled, display_order, enabled) -> fonte unica de verdade.
-- Decisao (§2.5): NAO se cria cyber_oat_observation_organization (M:N) sem necessidade real
--   comprovada por dados; sera adicionada em migration futura se um evento envolver varios orgaos.
-- Aplicacao: via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- =====================================================================================

-- ============================ organization: pertence a um tenant ============================
ALTER TABLE organization ADD COLUMN IF NOT EXISTS tenant_id           text;
ALTER TABLE organization ADD COLUMN IF NOT EXISTS attribution_enabled boolean NOT NULL DEFAULT true;

-- Backfill preservando dados: cada org atual e referenciada por exatamente um tenant na 001.
UPDATE organization o
   SET tenant_id = c.tenant_id
  FROM cyber_tenant_config c
 WHERE c.organization_id = o.organization_id
   AND o.tenant_id IS NULL;

-- Falha-segura: nao deixa o modelo inconsistente (aborta a 002 inteira se sobrar org sem tenant).
DO $$
DECLARE n int;
BEGIN
    SELECT count(*) INTO n FROM organization WHERE tenant_id IS NULL;
    IF n > 0 THEN
        RAISE EXCEPTION '002 abortada: % organizacao(oes) sem tenant_id apos backfill.', n;
    END IF;
END $$;

ALTER TABLE organization ALTER COLUMN tenant_id SET NOT NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_org_tenant') THEN
        ALTER TABLE organization ADD CONSTRAINT fk_org_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenant(tenant_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='uq_org_tenant_org') THEN
        ALTER TABLE organization ADD CONSTRAINT uq_org_tenant_org UNIQUE (tenant_id, organization_id);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_org_tenant_order ON organization (tenant_id, display_order, name);

-- ======================= cyber_tenant_config: capacidades do tenant =======================
ALTER TABLE cyber_tenant_config ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true;
COMMENT ON COLUMN cyber_tenant_config.organization_id IS
    'LEGADO (modelo tenant->1org da 001). Removido na 003 apos o backend novo (tenant->N orgs) validado. NAO usar como fonte de vinculo tenant-orgao.';

-- ======================= atribuicao de orgao em cyber_oat_observation =======================
ALTER TABLE cyber_oat_observation ADD COLUMN IF NOT EXISTS organization_id                     text;
ALTER TABLE cyber_oat_observation ADD COLUMN IF NOT EXISTS organization_attribution_status     text NOT NULL DEFAULT 'unassigned';
ALTER TABLE cyber_oat_observation ADD COLUMN IF NOT EXISTS organization_attribution_method     text NOT NULL DEFAULT 'unknown';
ALTER TABLE cyber_oat_observation ADD COLUMN IF NOT EXISTS organization_attribution_confidence text NOT NULL DEFAULT 'unavailable';
ALTER TABLE cyber_oat_observation ADD COLUMN IF NOT EXISTS organization_attribution_evidence   text;

DO $$ BEGIN
    -- FK composta: org atribuido DEVE pertencer ao mesmo tenant. MATCH SIMPLE => nao checa
    -- quando organization_id IS NULL (unassigned/ambiguous/unavailable ficam livres).
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_oat_org') THEN
        ALTER TABLE cyber_oat_observation ADD CONSTRAINT fk_oat_org
            FOREIGN KEY (tenant_id, organization_id) REFERENCES organization (tenant_id, organization_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_oat_attr_status') THEN
        ALTER TABLE cyber_oat_observation ADD CONSTRAINT ck_oat_attr_status
            CHECK (organization_attribution_status IN ('attributed','ambiguous','unassigned','unavailable'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_oat_attr_method') THEN
        ALTER TABLE cyber_oat_observation ADD CONSTRAINT ck_oat_attr_method
            CHECK (organization_attribution_method IN ('sep_instance','swp_instance','business_id',
                'product_instance_id','source_id','connector_id','custom_tag','organization_tag',
                'endpoint_group','asset_group','policy_mapping','sensor_id','account_mapping',
                'workload_mapping','oat_correlation','workbench_correlation','asset_correlation','unknown'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_oat_attr_conf') THEN
        ALTER TABLE cyber_oat_observation ADD CONSTRAINT ck_oat_attr_conf
            CHECK (organization_attribution_confidence IN ('high','medium','low','unavailable'));
    END IF;
    -- coerencia: attributed exige org; unassigned/ambiguous/unavailable exigem org NULL
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_oat_attr_coherence') THEN
        ALTER TABLE cyber_oat_observation ADD CONSTRAINT ck_oat_attr_coherence CHECK (
            (organization_attribution_status = 'attributed'  AND organization_id IS NOT NULL)
         OR (organization_attribution_status IN ('unassigned','ambiguous','unavailable') AND organization_id IS NULL)
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_oat_org         ON cyber_oat_observation (tenant_id, organization_id, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_attr_status ON cyber_oat_observation (tenant_id, organization_attribution_status);

-- ==================== atribuicao de orgao em cyber_workbench_indicator ====================
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS organization_id                     text;
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS organization_attribution_status     text NOT NULL DEFAULT 'unassigned';
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS organization_attribution_method     text NOT NULL DEFAULT 'unknown';
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS organization_attribution_confidence text NOT NULL DEFAULT 'unavailable';
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS organization_attribution_evidence   text;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_wb_org') THEN
        ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT fk_wb_org
            FOREIGN KEY (tenant_id, organization_id) REFERENCES organization (tenant_id, organization_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_wb_attr_status') THEN
        ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT ck_wb_attr_status
            CHECK (organization_attribution_status IN ('attributed','ambiguous','unassigned','unavailable'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_wb_attr_method') THEN
        ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT ck_wb_attr_method
            CHECK (organization_attribution_method IN ('sep_instance','swp_instance','business_id',
                'product_instance_id','source_id','connector_id','custom_tag','organization_tag',
                'endpoint_group','asset_group','policy_mapping','sensor_id','account_mapping',
                'workload_mapping','oat_correlation','workbench_correlation','asset_correlation','unknown'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_wb_attr_conf') THEN
        ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT ck_wb_attr_conf
            CHECK (organization_attribution_confidence IN ('high','medium','low','unavailable'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_wb_attr_coherence') THEN
        ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT ck_wb_attr_coherence CHECK (
            (organization_attribution_status = 'attributed'  AND organization_id IS NOT NULL)
         OR (organization_attribution_status IN ('unassigned','ambiguous','unavailable') AND organization_id IS NULL)
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_wb_org ON cyber_workbench_indicator (tenant_id, organization_id);

-- ======================= mapeamento dinamico instancia/tag/id -> orgao =======================
CREATE TABLE IF NOT EXISTS cyber_organization_mapping (
    mapping_id               bigserial   PRIMARY KEY,
    tenant_id                text        NOT NULL REFERENCES tenant(tenant_id),
    organization_id          text        NOT NULL,
    mapping_type             text        NOT NULL,
    mapping_value_normalized text        NOT NULL,
    mapping_value_hash       bytea       NOT NULL,   -- SHA-256 (32 bytes)
    source                   text,
    product_code             text,
    priority                 integer     NOT NULL DEFAULT 100,   -- menor = maior prioridade
    confidence               text        NOT NULL DEFAULT 'medium',
    enabled                  boolean     NOT NULL DEFAULT true,
    valid_from               timestamptz NOT NULL DEFAULT now(),
    valid_to                 timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_map_org FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organization (tenant_id, organization_id),
    CONSTRAINT ck_map_type CHECK (mapping_type IN ('sep_instance','swp_instance','business_id',
        'product_instance_id','source_id','connector_id','policy_id','endpoint_group','asset_group',
        'custom_tag','organization_tag','sensor_id','account_id','workload_id','domain',
        'other_validated_identifier')),
    CONSTRAINT ck_map_confidence CHECK (confidence IN ('high','medium','low')),
    CONSTRAINT ck_map_hashlen CHECK (octet_length(mapping_value_hash) = 32),
    CONSTRAINT ck_map_interval CHECK (valid_to IS NULL OR valid_to > valid_from)
);
-- lookup do coletor: por tenant + tipo + hash (apenas mapeamentos ativos)
CREATE INDEX IF NOT EXISTS ix_map_lookup ON cyber_organization_mapping
    (tenant_id, mapping_type, mapping_value_hash) WHERE enabled;
CREATE INDEX IF NOT EXISTS ix_map_org ON cyber_organization_mapping (tenant_id, organization_id);
-- evita duplicata exata de mapeamento (source/product tratados como '' quando nulos)
CREATE UNIQUE INDEX IF NOT EXISTS uq_map ON cyber_organization_mapping
    (tenant_id, mapping_type, mapping_value_hash, coalesce(source,''), coalesce(product_code,''), organization_id);

-- ======================= metricas de atribuicao em cyber_collection_state =======================
ALTER TABLE cyber_collection_state ADD COLUMN IF NOT EXISTS ext_accepted    integer NOT NULL DEFAULT 0;
ALTER TABLE cyber_collection_state ADD COLUMN IF NOT EXISTS attr_attributed integer NOT NULL DEFAULT 0;
ALTER TABLE cyber_collection_state ADD COLUMN IF NOT EXISTS attr_unassigned integer NOT NULL DEFAULT 0;
ALTER TABLE cyber_collection_state ADD COLUMN IF NOT EXISTS attr_ambiguous  integer NOT NULL DEFAULT 0;
ALTER TABLE cyber_collection_state ADD COLUMN IF NOT EXISTS attr_failed     integer NOT NULL DEFAULT 0;

-- =====================================================================================
-- ROLLBACK (executar manualmente; aditivo -> remove somente o que a 002 criou).
-- NAO apaga dados de negocio (apenas colunas/objetos adicionados). Apos, remover o registro:
--   DELETE FROM schema_migrations WHERE version='002_cyber_tenant_organizations';
-- -------------------------------------------------------------------------------------
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_organization_mapping CASCADE;
-- ALTER TABLE cyber_collection_state
--   DROP COLUMN IF EXISTS ext_accepted, DROP COLUMN IF EXISTS attr_attributed,
--   DROP COLUMN IF EXISTS attr_unassigned, DROP COLUMN IF EXISTS attr_ambiguous,
--   DROP COLUMN IF EXISTS attr_failed;
-- ALTER TABLE cyber_workbench_indicator
--   DROP CONSTRAINT IF EXISTS fk_wb_org, DROP CONSTRAINT IF EXISTS ck_wb_attr_status,
--   DROP CONSTRAINT IF EXISTS ck_wb_attr_method, DROP CONSTRAINT IF EXISTS ck_wb_attr_conf,
--   DROP CONSTRAINT IF EXISTS ck_wb_attr_coherence,
--   DROP COLUMN IF EXISTS organization_id, DROP COLUMN IF EXISTS organization_attribution_status,
--   DROP COLUMN IF EXISTS organization_attribution_method, DROP COLUMN IF EXISTS organization_attribution_confidence,
--   DROP COLUMN IF EXISTS organization_attribution_evidence;
-- ALTER TABLE cyber_oat_observation
--   DROP CONSTRAINT IF EXISTS fk_oat_org, DROP CONSTRAINT IF EXISTS ck_oat_attr_status,
--   DROP CONSTRAINT IF EXISTS ck_oat_attr_method, DROP CONSTRAINT IF EXISTS ck_oat_attr_conf,
--   DROP CONSTRAINT IF EXISTS ck_oat_attr_coherence,
--   DROP COLUMN IF EXISTS organization_id, DROP COLUMN IF EXISTS organization_attribution_status,
--   DROP COLUMN IF EXISTS organization_attribution_method, DROP COLUMN IF EXISTS organization_attribution_confidence,
--   DROP COLUMN IF EXISTS organization_attribution_evidence;
-- ALTER TABLE cyber_tenant_config DROP COLUMN IF EXISTS enabled;
-- DROP INDEX IF EXISTS ix_org_tenant_order;
-- ALTER TABLE organization DROP CONSTRAINT IF EXISTS uq_org_tenant_org,
--   DROP CONSTRAINT IF EXISTS fk_org_tenant,
--   DROP COLUMN IF EXISTS attribution_enabled, DROP COLUMN IF EXISTS tenant_id;
-- DELETE FROM schema_migrations WHERE version='002_cyber_tenant_organizations';
-- COMMIT;
-- =====================================================================================
