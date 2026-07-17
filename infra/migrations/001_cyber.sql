-- =====================================================================================
-- 001_cyber.sql  |  Cyber multi-tenant / multi-fonte (OAT + Workbench + Suspicious Objects)
-- =====================================================================================
-- Escopo .....: 11 tabelas (cadastro central + modelo Cyber), PostgreSQL COMUM
--               (SEM TimescaleDB/hypertable/continuous aggregate — ver correcao #7).
-- Aplicacao ..: ATOMICA (BEGIN/COMMIT) e IDEMPOTENTE (CREATE ... IF NOT EXISTS +
--               INSERT ... ON CONFLICT DO NOTHING). Re-executar = no-op sem erro.
-- Rollback ...: bloco comentado no final (DROP em ordem reversa de dependencia).
-- ATENCAO ....: NAO aplicar no banco de producao (socdash) sem confirmacao explicita.
--               Validada apenas em banco temporario descartavel.
-- Dados ......: nenhum dado operacional e semeado; apenas o cadastro central
--               (organization/tenant). Tokens de API NUNCA ficam no banco (.env).
-- -------------------------------------------------------------------------------------
-- Correcoes incorporadas (v3 -> migration): #1 11 tabelas | #2 country em cyber_indicator
--   (sem ix_oat_country) | #3 FKs reais Workbench<->OAT com PK surrogate | #4 sem
--   organization_id em cyber_oat_observation | #5 historico SO com FK+CHECK intervalo |
--   #8 CHECKs de dominio | #9 enforcement_capability com status/frescor | #10
--   discard_sample com indice+retencao. (#6 janela adaptativa e #7 caveat de benchmark
--   sao decisoes de coletor/documentacao — nao geram objeto de schema.)
-- =====================================================================================

BEGIN;

-- =====================================================================================
-- CADASTRO CENTRAL DINAMICO (organization 1—N tenant). Sem listas hardcoded no codigo.
-- =====================================================================================

-- (1) organization ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organization (
    organization_id  text        PRIMARY KEY,
    name             text        NOT NULL,
    display_order    integer     NOT NULL DEFAULT 0,
    cyber_enabled    boolean     NOT NULL DEFAULT true,
    enabled          boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- (2) tenant ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant (
    tenant_id                   text        PRIMARY KEY,
    organization_id             text        NOT NULL REFERENCES organization(organization_id),
    name                        text        NOT NULL,
    region_base                 text        NOT NULL DEFAULT 'https://api.xdr.trendmicro.com',
    enabled                     boolean     NOT NULL DEFAULT true,
    cyber_enabled               boolean     NOT NULL DEFAULT true,
    oat_enabled                 boolean     NOT NULL DEFAULT true,
    workbench_enabled           boolean     NOT NULL DEFAULT true,
    suspicious_objects_enabled  boolean     NOT NULL DEFAULT true,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_tenant_org ON tenant (organization_id);

-- =====================================================================================
-- MODELO CYBER
-- =====================================================================================

-- (3) cyber_indicator — entidade canonica do indicador externo (ip/domain/url).
--     Detem a geolocalizacao (correcao #2: country/lat/long/geo vivem AQUI; agregacoes
--     geograficas do OAT saem por JOIN a esta tabela).
CREATE TABLE IF NOT EXISTS cyber_indicator (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_type        text        NOT NULL,
    value_normalized      text        NOT NULL,
    value_raw             text        NOT NULL,
    -- geolocalizacao (correcao #2 e #8: geo_status/method/lat/long com CHECK)
    geo_status            text,
    geo_resolution_method text,
    country               text,
    country_iso2          text,
    city                  text,
    latitude              numeric(9,6),
    longitude             numeric(9,6),
    resolved_ip           inet,
    geo_resolved_at       timestamptz,
    geo_expires_at        timestamptz,
    first_seen_at         timestamptz NOT NULL,
    last_seen_at          timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_cyber_indicator PRIMARY KEY (tenant_id, indicator_type, value_normalized),
    CONSTRAINT ck_indicator_type   CHECK (indicator_type IN ('ip','domain','url')),
    CONSTRAINT ck_indicator_geostat CHECK (geo_status IS NULL OR geo_status IN
        ('ok','private','nogeo','unresolved','pending')),
    CONSTRAINT ck_indicator_geomethod CHECK (geo_resolution_method IS NULL OR
        geo_resolution_method IN ('direct_ip','dns','none')),
    CONSTRAINT ck_indicator_lat CHECK (latitude  IS NULL OR (latitude  BETWEEN -90  AND 90)),
    CONSTRAINT ck_indicator_lon CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180))
);
-- correcao #2: indice de pais em cyber_indicator (NAO em cyber_oat_observation)
CREATE INDEX IF NOT EXISTS ix_indicator_country ON cyber_indicator (country) WHERE country IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_indicator_lastseen ON cyber_indicator (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_indicator_geoexp   ON cyber_indicator (geo_expires_at) WHERE geo_expires_at IS NOT NULL;

-- (4) cyber_oat_observation — fluxo de observacoes do OAT (correcao #4: SEM
--     organization_id; o orgao deriva de tenant.organization_id via JOIN).
--     Idempotencia: UNIQUE (tenant_id, source, source_event_id, indicator_id,
--     source_field, indicator_role). PK surrogate observation_id (alvo de FK do link).
CREATE TABLE IF NOT EXISTS cyber_oat_observation (
    observation_id        bigserial   PRIMARY KEY,
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    source                text        NOT NULL,
    product_code          text,
    source_event_id       text        NOT NULL,   -- uuid da detection OAT
    indicator_id          text        NOT NULL,   -- id do indicador OU sha1(type|value_norm)
    indicator_type        text        NOT NULL,
    value_normalized      text        NOT NULL,
    value_raw             text        NOT NULL,
    source_field          text        NOT NULL,   -- highlightedObject.field / denyListHost / ...
    indicator_role        text        NOT NULL,   -- attacker / c2 / peer / target ...
    event_time            timestamptz NOT NULL,   -- detectionTime (correcao D1)
    ingest_time           timestamptz,
    severity              text        NOT NULL,
    -- 3 dimensoes de acao independentes (correcoes anteriores + #8 CHECK)
    enforcement_status    text        NOT NULL DEFAULT 'unknown',
    action_field          text,
    action_value_raw      text,
    block_policy_matched  boolean     NOT NULL DEFAULT false,
    policy_match_basis    text        NOT NULL DEFAULT 'unavailable',
    mitre_tactics         text[],
    mitre_techniques      text[],
    victim_entity         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_oat_observation UNIQUE
        (tenant_id, source, source_event_id, indicator_id, source_field, indicator_role),
    CONSTRAINT ck_oat_indtype   CHECK (indicator_type IN ('ip','domain','url')),
    CONSTRAINT ck_oat_severity  CHECK (severity IN ('high','critical')),
    CONSTRAINT ck_oat_enforce   CHECK (enforcement_status IN
        ('prevented_confirmed','allowed_confirmed','observed_not_prevented','observed','unknown')),
    CONSTRAINT ck_oat_basis     CHECK (policy_match_basis IN ('event_time','current_state','unavailable')),
    -- FK real ao indicador canonico (forca upsert do indicador antes da observacao)
    CONSTRAINT fk_oat_indicator FOREIGN KEY (tenant_id, indicator_type, value_normalized)
        REFERENCES cyber_indicator (tenant_id, indicator_type, value_normalized)
);
CREATE INDEX IF NOT EXISTS ix_oat_event      ON cyber_oat_observation (event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_tenant_evt ON cyber_oat_observation (tenant_id, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_enforce    ON cyber_oat_observation (tenant_id, enforcement_status, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_indicator  ON cyber_oat_observation (tenant_id, indicator_type, value_normalized);
CREATE INDEX IF NOT EXISTS ix_oat_source     ON cyber_oat_observation (tenant_id, source, event_time DESC);

-- (5) cyber_workbench_indicator — indicadores externos vindos de alertas Workbench.
--     Correcao #3: PK surrogate workbench_indicator_pk (alvo de FK do link) +
--     UNIQUE natural (tenant_id, alert_id, indicator_id).
CREATE TABLE IF NOT EXISTS cyber_workbench_indicator (
    workbench_indicator_pk bigserial   PRIMARY KEY,
    tenant_id              text        NOT NULL REFERENCES tenant(tenant_id),
    alert_id               text        NOT NULL,   -- WB-xxxx
    indicator_id           text        NOT NULL,
    indicator_type         text        NOT NULL,
    value_raw              text        NOT NULL,
    value_normalized       text        NOT NULL,
    indicator_role         text,
    alert_severity         text,
    model                  text,
    provider               text,
    provenance             text[],
    alert_created_at       timestamptz NOT NULL,
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at           timestamptz NOT NULL DEFAULT now(),
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_wb_indicator UNIQUE (tenant_id, alert_id, indicator_id),
    CONSTRAINT ck_wb_indtype CHECK (indicator_type IN ('ip','domain','url'))
);
CREATE INDEX IF NOT EXISTS ix_wb_tenant_created ON cyber_workbench_indicator (tenant_id, alert_created_at DESC);
CREATE INDEX IF NOT EXISTS ix_wb_value          ON cyber_workbench_indicator (tenant_id, indicator_type, value_normalized);

-- (6) cyber_workbench_oat_link — correlacao M:N Workbench<->OAT (correcao #3).
--     FKs REAIS para as PKs surrogate; ON DELETE CASCADE dos dois lados.
CREATE TABLE IF NOT EXISTS cyber_workbench_oat_link (
    tenant_id              text        NOT NULL REFERENCES tenant(tenant_id),
    workbench_indicator_pk bigint      NOT NULL
        REFERENCES cyber_workbench_indicator(workbench_indicator_pk) ON DELETE CASCADE,
    oat_observation_id     bigint      NOT NULL
        REFERENCES cyber_oat_observation(observation_id) ON DELETE CASCADE,
    link_method            text        NOT NULL,   -- ex.: same_value / same_alert_time
    link_confidence        text        NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_wb_oat_link PRIMARY KEY (workbench_indicator_pk, oat_observation_id),
    CONSTRAINT ck_link_confidence CHECK (link_confidence IN ('high','medium','low'))
);
CREATE INDEX IF NOT EXISTS ix_wblink_obs    ON cyber_workbench_oat_link (oat_observation_id);
CREATE INDEX IF NOT EXISTS ix_wblink_tenant ON cyber_workbench_oat_link (tenant_id);

-- (7) cyber_suspicious_object — estado ATUAL da block-list curada (nao e stream).
CREATE TABLE IF NOT EXISTS cyber_suspicious_object (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_type        text        NOT NULL,
    value_normalized      text        NOT NULL,
    value_raw             text        NOT NULL,
    scan_action           text,
    risk_level            text,
    in_exception_list     boolean     NOT NULL DEFAULT false,
    notes                 text,
    api_last_modified_at  timestamptz,
    expired_at            timestamptz,
    first_seen_at         timestamptz NOT NULL,
    last_seen_at          timestamptz NOT NULL,
    is_active             boolean     NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_suspicious_object PRIMARY KEY (tenant_id, indicator_type, value_normalized),
    CONSTRAINT ck_so_type CHECK (indicator_type IN
        ('ip','domain','url','fileSha1','fileSha256','senderMailAddress'))
);
CREATE INDEX IF NOT EXISTS ix_so_active ON cyber_suspicious_object (tenant_id, is_active);

-- (8) cyber_suspicious_object_history — historico temporal do SO (correcao #5:
--     FK tenant + CHECK de intervalo). Transicao = fecha intervalo atual (valid_to) +
--     insere novo + atualiza cyber_suspicious_object, na MESMA transacao. Primeira
--     sincronizacao completa registra o ESTADO da primeira coleta, sem historico
--     retroativo (valid_from = momento da 1a coleta, change_type='added').
CREATE TABLE IF NOT EXISTS cyber_suspicious_object_history (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_type        text        NOT NULL,
    value_normalized      text        NOT NULL,
    valid_from            timestamptz NOT NULL,
    valid_to              timestamptz,
    scan_action           text,
    risk_level            text,
    in_exception_list     boolean,
    change_type           text        NOT NULL,
    policy_match_basis    text        NOT NULL DEFAULT 'current_state',
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_so_history PRIMARY KEY (tenant_id, indicator_type, value_normalized, valid_from),
    CONSTRAINT ck_soh_change CHECK (change_type IN ('added','modified','removed')),
    CONSTRAINT ck_soh_basis  CHECK (policy_match_basis IN ('event_time','current_state','unavailable')),
    CONSTRAINT ck_soh_interval CHECK (valid_to IS NULL OR valid_to > valid_from)
);
CREATE INDEX IF NOT EXISTS ix_soh_value ON cyber_suspicious_object_history
    (tenant_id, indicator_type, value_normalized, valid_from DESC);
CREATE INDEX IF NOT EXISTS ix_soh_open  ON cyber_suspicious_object_history
    (tenant_id, indicator_type, value_normalized) WHERE valid_to IS NULL;

-- (9) cyber_collection_state — watermark/telemetria por (tenant, collector, source,
--     severity_scope). Watermark independente por severidade (correcao: severity_scope).
CREATE TABLE IF NOT EXISTS cyber_collection_state (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    collector             text        NOT NULL,          -- oat / workbench / suspicious_object
    source                text        NOT NULL DEFAULT 'all',
    severity_scope        text        NOT NULL DEFAULT 'all',
    watermark_event_time  timestamptz,                   -- fim do ultimo intervalo contiguo completo
    watermark_ingest_time timestamptz,
    cursor                text,
    window_start          timestamptz,
    window_end            timestamptz,
    last_attempt_at       timestamptz,
    last_success_at       timestamptz,
    last_error            text,
    pages                 integer     NOT NULL DEFAULT 0,
    received              integer     NOT NULL DEFAULT 0,
    inserted              integer     NOT NULL DEFAULT 0,
    updated               integer     NOT NULL DEFAULT 0,
    duplicates            integer     NOT NULL DEFAULT 0,
    http_429              integer     NOT NULL DEFAULT 0,
    retries               integer     NOT NULL DEFAULT 0,
    duration_ms           integer,
    saturated             boolean     NOT NULL DEFAULT false,
    status                text,
    -- metricas de descarte agregadas (detalhe amostrado vai para cyber_discard_sample)
    disc_severity         integer     NOT NULL DEFAULT 0,
    disc_non_public       integer     NOT NULL DEFAULT 0,
    disc_role             integer     NOT NULL DEFAULT 0,
    disc_ambiguity        integer     NOT NULL DEFAULT 0,
    disc_type             integer     NOT NULL DEFAULT 0,
    disc_action           integer     NOT NULL DEFAULT 0,
    disc_duplicate        integer     NOT NULL DEFAULT 0,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_collection_state PRIMARY KEY (tenant_id, collector, source, severity_scope),
    CONSTRAINT ck_cs_severity_scope CHECK (severity_scope IN ('high','critical','all')),
    CONSTRAINT ck_cs_status CHECK (status IS NULL OR status IN
        ('ok','partial','error','unavailable','stale'))
);

-- (10) cyber_enforcement_capability — capacidade de enforcement por
--      (tenant, source, product_code). Correcao #9: status/reason/evidence_field/
--      last_seen_at/expires_at para NAO tratar capacidade obsoleta como atual.
CREATE TABLE IF NOT EXISTS cyber_enforcement_capability (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    source                text        NOT NULL,
    product_code          text        NOT NULL DEFAULT 'all',
    capability            text        NOT NULL,   -- none / partial / full
    status                text        NOT NULL DEFAULT 'unknown',
    reason                text,
    evidence_field        text,
    samples_seen          integer     NOT NULL DEFAULT 0,
    last_seen_at          timestamptz,
    expires_at            timestamptz,
    computed_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_enforcement_capability PRIMARY KEY (tenant_id, source, product_code),
    CONSTRAINT ck_cap_value  CHECK (capability IN ('none','partial','full')),
    CONSTRAINT ck_cap_status CHECK (status IN ('current','stale','unknown'))
);
CREATE INDEX IF NOT EXISTS ix_cap_expires ON cyber_enforcement_capability (expires_at)
    WHERE expires_at IS NOT NULL;

-- (11) cyber_discard_sample — amostras (sanitizadas) de itens descartados p/ auditoria.
--      Correcao #10: indice em sampled_at + retencao 30h (job externo). Limite por
--      tenant e por motivo aplicado na escrita pelo coletor (ring/reservoir); valores
--      sanitizados (truncados/mascarados). Ao atingir o limite: descarta a amostra
--      (nunca o contador agregado em cyber_collection_state, que segue somando).
CREATE TABLE IF NOT EXISTS cyber_discard_sample (
    id                    bigserial   PRIMARY KEY,
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    collector             text,
    source                text,
    reason                text        NOT NULL,   -- severity/non_public/role/ambiguity/type/action/duplicate
    indicator_type        text,
    value_sanitized       text,
    source_field          text,
    detail_sanitized      text,
    sampled_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_discard_reason CHECK (reason IN
        ('severity','non_public','role','ambiguity','type','action','duplicate','other'))
);
-- correcao #10: indice p/ purga por tempo (retencao 30h aplicada por job)
CREATE INDEX IF NOT EXISTS ix_discard_sampled ON cyber_discard_sample (sampled_at);
CREATE INDEX IF NOT EXISTS ix_discard_tenant  ON cyber_discard_sample (tenant_id, reason, sampled_at DESC);

-- =====================================================================================
-- SEED do cadastro central (idempotente). Reflete os 4 tenants do ambiente.
-- NAO inclui tokens (ficam no .env por tenant_id).
-- =====================================================================================
INSERT INTO organization (organization_id, name, display_order) VALUES
    ('org-prodesp', 'Prodesp', 1),
    ('org-detran',  'Detran',  2),
    ('org-iamspe',  'Iamspe',  3),
    ('org-sggd',    'SGGD',    4)
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO tenant (tenant_id, organization_id, name) VALUES
    ('prodesp-sp', 'org-prodesp', 'Prodesp'),
    ('detran-sp',  'org-detran',  'Detran'),
    ('iamspe-sp',  'org-iamspe',  'Iamspe'),
    ('sggd',       'org-sggd',    'SGGD')
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;

-- =====================================================================================
-- ROLLBACK (executar manualmente para desfazer a migration). Ordem reversa + CASCADE.
-- -------------------------------------------------------------------------------------
-- BEGIN;
-- DROP TABLE IF EXISTS cyber_discard_sample            CASCADE;
-- DROP TABLE IF EXISTS cyber_enforcement_capability    CASCADE;
-- DROP TABLE IF EXISTS cyber_collection_state          CASCADE;
-- DROP TABLE IF EXISTS cyber_suspicious_object_history CASCADE;
-- DROP TABLE IF EXISTS cyber_suspicious_object         CASCADE;
-- DROP TABLE IF EXISTS cyber_workbench_oat_link        CASCADE;
-- DROP TABLE IF EXISTS cyber_workbench_indicator       CASCADE;
-- DROP TABLE IF EXISTS cyber_oat_observation           CASCADE;
-- DROP TABLE IF EXISTS cyber_indicator                 CASCADE;
-- DROP TABLE IF EXISTS tenant                          CASCADE;
-- DROP TABLE IF EXISTS organization                    CASCADE;
-- COMMIT;
-- =====================================================================================
