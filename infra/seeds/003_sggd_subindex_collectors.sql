-- =====================================================================================
-- 003_sggd_subindex_collectors.sql  |  Coletores de origem -> subindice (console SGGD)
-- Dados de ambiente (nao e migration). Idempotente. Aplicar a parte do migrate.sh.
-- =====================================================================================
INSERT INTO cyber_subindex_collector (tenant_id, collector_id, collector_name, subindex) VALUES
  ('sggd','12e12fcf-1739-44c6-8383-cbf5691c77ff','Waf SGGD','SGGD'),
  ('sggd','9f91aa72-9422-4422-a68a-a0c4d9a137d0','Firewall SGGD','SGGD'),
  ('sggd','80ac1456-d117-4f13-9634-2d42a31d534b','CyberArk-EPM SGGD','SGGD'),
  ('sggd','95d84033-f3ea-4bf3-bd05-434a3cfcf296','Cyberark-PAM-6520 SGGD','SGGD')
ON CONFLICT (tenant_id, collector_id) DO UPDATE
  SET collector_name=EXCLUDED.collector_name, subindex=EXCLUDED.subindex;

-- default: workbenches do SGGD sem coletor mapeado (deteccoes nativas) -> subindice base 'SGGD'
UPDATE cyber_tenant_config SET default_subindex='SGGD' WHERE tenant_id='sggd';
