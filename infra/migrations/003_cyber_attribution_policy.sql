-- =====================================================================================
-- 003_cyber_attribution_policy.sql  |  Politica de atribuicao por instancia + preservacao de IDs
-- =====================================================================================
-- Contexto: o tenant SGGD e segmentado por INSTANCIAS distintas de SEP/SWP (PGE/SPPREV/CGE/
-- SGRI/SGGD). Enquanto nao houver mapeamento instancia->orgao, os eventos ficam unassigned
-- com method='instance_mapping_pending', preservando TODOS os identificadores de instancia
-- para reatribuicao futura SEM nova coleta.
-- Aditiva; aplicada via infra/migrate.sh (transacao + checksum). Sem BEGIN/COMMIT aqui.
-- NOTA de numeracao: a remocao do legado cyber_tenant_config.organization_id (§25) fica para
-- uma migration posterior (apos backend novo validado); esta 003 e pre-requisito dos coletores.
-- =====================================================================================

-- modo de atribuicao por tenant (config, NAO hardcoded em codigo; valores setados via seed)
ALTER TABLE cyber_tenant_config ADD COLUMN IF NOT EXISTS attribution_mode text NOT NULL DEFAULT 'mapping';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ck_tcfg_attr_mode') THEN
        ALTER TABLE cyber_tenant_config ADD CONSTRAINT ck_tcfg_attr_mode
            CHECK (attribution_mode IN ('single_org','instance','mapping','none'));
    END IF;
END $$;

-- extensao do enum de metodo de atribuicao: + single_org, instance_mapping_pending,
-- management_scope_instance, management_scope_group (recria o CHECK; superset e seguro).
DO $$
DECLARE
    methods text := $m$organization_attribution_method IN (
        'sep_instance','swp_instance','management_scope_instance','management_scope_group',
        'product_instance_id','business_id','source_id','connector_id','custom_tag',
        'organization_tag','endpoint_group','asset_group','policy_mapping','sensor_id',
        'account_mapping','workload_mapping','oat_correlation','workbench_correlation',
        'asset_correlation','single_org','instance_mapping_pending','unknown')$m$;
BEGIN
    ALTER TABLE cyber_oat_observation      DROP CONSTRAINT IF EXISTS ck_oat_attr_method;
    EXECUTE 'ALTER TABLE cyber_oat_observation ADD CONSTRAINT ck_oat_attr_method CHECK ('||methods||')';
    ALTER TABLE cyber_workbench_indicator  DROP CONSTRAINT IF EXISTS ck_wb_attr_method;
    EXECUTE 'ALTER TABLE cyber_workbench_indicator ADD CONSTRAINT ck_wb_attr_method CHECK ('||methods||')';
END $$;

-- extensao dos tipos de mapeamento: + management_scope_instance, management_scope_group
DO $$ BEGIN
    ALTER TABLE cyber_organization_mapping DROP CONSTRAINT IF EXISTS ck_map_type;
    ALTER TABLE cyber_organization_mapping ADD CONSTRAINT ck_map_type CHECK (mapping_type IN (
        'sep_instance','swp_instance','management_scope_instance','management_scope_group',
        'business_id','product_instance_id','source_id','connector_id','policy_id','endpoint_group',
        'asset_group','custom_tag','organization_tag','sensor_id','account_id','workload_id','domain',
        'other_validated_identifier'));
END $$;

-- identificadores de instancia PRESERVADOS por observacao (reatribuicao sem nova coleta).
-- JSONB estruturado: {managementScopeInstanceId, managementScopeGroupId, instanceId,
-- productInstanceId, sourceId, connectorId, endpointGUID, groupId, interestedGroup, appGroup,
-- customAssetTags, platformAssetTags, source, productCode, ...} (somente os presentes).
ALTER TABLE cyber_oat_observation     ADD COLUMN IF NOT EXISTS attribution_identifiers jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE cyber_workbench_indicator ADD COLUMN IF NOT EXISTS attribution_identifiers jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS ix_oat_attr_ids ON cyber_oat_observation     USING gin (attribution_identifiers);
CREATE INDEX IF NOT EXISTS ix_wb_attr_ids  ON cyber_workbench_indicator USING gin (attribution_identifiers);

-- =====================================================================================
-- ROLLBACK:
-- BEGIN;
-- DROP INDEX IF EXISTS ix_oat_attr_ids; DROP INDEX IF EXISTS ix_wb_attr_ids;
-- ALTER TABLE cyber_oat_observation     DROP COLUMN IF EXISTS attribution_identifiers;
-- ALTER TABLE cyber_workbench_indicator DROP COLUMN IF EXISTS attribution_identifiers;
-- -- (os CHECK ampliados podem permanecer; para reverter estritamente, recriar as versoes da 002)
-- ALTER TABLE cyber_tenant_config DROP CONSTRAINT IF EXISTS ck_tcfg_attr_mode, DROP COLUMN IF EXISTS attribution_mode;
-- DELETE FROM schema_migrations WHERE version='003_cyber_attribution_policy';
-- COMMIT;
-- =====================================================================================
