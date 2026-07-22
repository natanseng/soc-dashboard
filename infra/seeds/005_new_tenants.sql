-- 005_new_tenants.sql — adiciona 4 consoles: Poupatempo, SPI, Alesp, CPTM (padrao single_org, como detran/iamspe/prodesp).
-- Idempotente (ON CONFLICT DO NOTHING). Tokens ficam no .env (V1_API_TOKEN_<LABEL>), nunca no banco.
BEGIN;

INSERT INTO tenant (tenant_id, display_name) VALUES
  ('poupatempo', 'Poupatempo'),
  ('spi',        'SPI'),
  ('alesp',      'Alesp'),
  ('cptm',       'CPTM')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO organization (organization_id, name, tenant_id, display_order) VALUES
  ('org-poupatempo', 'Poupatempo', 'poupatempo', 0),
  ('org-spi',        'SPI',        'spi',        0),
  ('org-alesp',      'Alesp',      'alesp',      0),
  ('org-cptm',       'CPTM',       'cptm',       0)
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO cyber_tenant_config (tenant_id, organization_id, attribution_mode) VALUES
  ('poupatempo', 'org-poupatempo', 'single_org'),
  ('spi',        'org-spi',        'single_org'),
  ('alesp',      'org-alesp',      'single_org'),
  ('cptm',       'org-cptm',       'single_org')
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
