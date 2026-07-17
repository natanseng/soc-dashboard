-- =====================================================================================
-- 002_cyber_attribution_modes.sql  |  SEED (dado do ambiente) — modo de atribuicao por tenant
-- =====================================================================================
-- Configuracao do ambiente atual (NAO e hardcode em codigo: o coletor le attribution_mode
-- dinamicamente). Idempotente. Novos tenants nascem com default 'mapping' (unassigned ate
-- haver mapeamento; nunca atribuicao artificial).
--   * prodesp-sp/detran-sp/iamspe-sp: 1 orgao real cada -> 'single_org'.
--   * sggd: segmentado por instancias SEP/SWP (PGE/SPPREV/CGE/SGRI/SGGD) -> 'instance'
--     (eventos ficam unassigned + method=instance_mapping_pending ate cadastro de mapeamento).
-- =====================================================================================
UPDATE cyber_tenant_config SET attribution_mode = 'single_org', updated_at = now()
 WHERE tenant_id IN ('prodesp-sp', 'detran-sp', 'iamspe-sp');

UPDATE cyber_tenant_config SET attribution_mode = 'instance', updated_at = now()
 WHERE tenant_id = 'sggd';
