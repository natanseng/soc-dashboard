-- =====================================================================================
-- 004_waf_collectors.sql  |  Coletores WAF (indicador "Bloqueios WAF"). Idempotente.
-- =====================================================================================
INSERT INTO cyber_waf_collector (tenant_id, collector_id, collector_name) VALUES
  ('sggd',      '12e12fcf-1739-44c6-8383-cbf5691c77ff', 'Waf SGGD'),
  ('detran-sp', '92f40cfd-c688-4c8b-a0da-2403bfafb9de', 'Waf Detran')
ON CONFLICT (tenant_id, collector_id) DO UPDATE SET collector_name=EXCLUDED.collector_name;
