-- =====================================================================================
-- rollback_001_cyber_current_environment.sql  |  Rollback SEGURO do seed do ambiente
-- =====================================================================================
-- Desfaz APENAS o que o seed 001_cyber_current_environment.sql inseriu, com garantias:
--   * Remove primeiro os registros de cyber_tenant_config (os 4 do seed).
--   * Remove as organizacoes do seed SOMENTE se nao possuirem referencias.
--   * Remove Detran/Iamspe/SGGD de `tenant` SOMENTE se: forem do seed, sem NENHUMA
--     referencia (base + cyber) e nao estiverem em uso. NUNCA remove prodesp-sp
--     (ja existia antes desta demanda, criado pelo init.sql).
--   * Roda em transacao; FALHA de forma segura (RAISE EXCEPTION -> rollback) se houver
--     referencia; NAO usa CASCADE para remover de `tenant`.
-- Idempotente: se ja tiver sido revertido, os DELETEs afetam 0 linhas e o bloco conclui.
-- =====================================================================================

BEGIN;

DO $$
DECLARE
    seed_tenants text[] := ARRAY['detran-sp','iamspe-sp','sggd'];              -- NUNCA prodesp-sp
    seed_orgs    text[] := ARRAY['org-prodesp','org-detran','org-iamspe','org-sggd'];
    seed_cfg     text[] := ARRAY['prodesp-sp','detran-sp','iamspe-sp','sggd']; -- configs criadas pelo seed
    t       text;
    reffed  text;
    n_cfg   int;
    n_org   int;
BEGIN
    -- 1) Remove as configuracoes Cyber criadas pelo seed (inclui a de prodesp-sp, que e do seed;
    --    a LINHA de tenant prodesp-sp permanece).
    DELETE FROM cyber_tenant_config WHERE tenant_id = ANY(seed_cfg);
    GET DIAGNOSTICS n_cfg = ROW_COUNT;

    -- 2) Remove as organizacoes do seed SOMENTE se nao houver referencia em cyber_tenant_config
    --    (unica tabela que referencia organization).
    DELETE FROM organization o
     WHERE o.organization_id = ANY(seed_orgs)
       AND NOT EXISTS (SELECT 1 FROM cyber_tenant_config c WHERE c.organization_id = o.organization_id);
    GET DIAGNOSTICS n_org = ROW_COUNT;

    -- 3) Remove os tenants do seed (nunca prodesp-sp), SOMENTE se nao houver NENHUMA
    --    referencia em qualquer tabela filha (base + cyber). Se houver, FALHA com seguranca.
    FOREACH t IN ARRAY seed_tenants LOOP
        SELECT string_agg(src, ', ') INTO reffed FROM (
            SELECT 'asset'                            AS src WHERE EXISTS (SELECT 1 FROM asset                            WHERE tenant_id = t)
            UNION ALL SELECT 'wb_alert'                      WHERE EXISTS (SELECT 1 FROM wb_alert                         WHERE tenant_id = t)
            UNION ALL SELECT 'sec_event'                     WHERE EXISTS (SELECT 1 FROM sec_event                        WHERE tenant_id = t)
            UNION ALL SELECT 'posture_snapshot'              WHERE EXISTS (SELECT 1 FROM posture_snapshot                 WHERE tenant_id = t)
            UNION ALL SELECT 'vulnerability'                 WHERE EXISTS (SELECT 1 FROM vulnerability                    WHERE tenant_id = t)
            UNION ALL SELECT 'attack_geo'                    WHERE EXISTS (SELECT 1 FROM attack_geo                       WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_tenant_config'           WHERE EXISTS (SELECT 1 FROM cyber_tenant_config              WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_indicator'               WHERE EXISTS (SELECT 1 FROM cyber_indicator                  WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_oat_observation'         WHERE EXISTS (SELECT 1 FROM cyber_oat_observation            WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_workbench_indicator'     WHERE EXISTS (SELECT 1 FROM cyber_workbench_indicator        WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_workbench_oat_link'      WHERE EXISTS (SELECT 1 FROM cyber_workbench_oat_link         WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_suspicious_object'       WHERE EXISTS (SELECT 1 FROM cyber_suspicious_object          WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_suspicious_object_history' WHERE EXISTS (SELECT 1 FROM cyber_suspicious_object_history WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_collection_state'        WHERE EXISTS (SELECT 1 FROM cyber_collection_state           WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_enforcement_capability'  WHERE EXISTS (SELECT 1 FROM cyber_enforcement_capability     WHERE tenant_id = t)
            UNION ALL SELECT 'cyber_discard_sample'          WHERE EXISTS (SELECT 1 FROM cyber_discard_sample             WHERE tenant_id = t)
        ) refs;

        IF reffed IS NOT NULL THEN
            RAISE EXCEPTION 'Rollback do seed ABORTADO: tenant "%" possui referencias em: %. Remova as dependencias primeiro (nao usar CASCADE).', t, reffed;
        END IF;

        DELETE FROM tenant WHERE tenant_id = t;   -- sem CASCADE; prodesp-sp nunca esta na lista
    END LOOP;

    RAISE NOTICE 'Rollback do seed OK: cyber_tenant_config removidas=%, organization removidas=%, tenants do seed removidos (se sem ref)=%. prodesp-sp preservado.',
                 n_cfg, n_org, array_to_string(seed_tenants, ',');
END $$;

COMMIT;
