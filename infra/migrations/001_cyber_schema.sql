-- =====================================================================================
-- 001_cyber_schema.sql  |  Schema Cyber multi-tenant/multi-fonte (OAT + Workbench + SO)
-- =====================================================================================
-- Pre-requisito: a tabela base `tenant` (init.sql) DEVE existir. Esta migration NAO cria
--   nem altera `tenant`; apenas a REUTILIZA (FKs -> tenant(tenant_id)) e a estende via
--   `cyber_tenant_config` (1:1) + `organization`. Registro unico de tenant preservado.
-- Aplicacao: via infra/migrate.sh, que encapsula ESTE arquivo em UMA transacao e registra
--   version+checksum em schema_migrations. Por isso o arquivo NAO contem BEGIN/COMMIT.
-- Idempotencia: CREATE ... IF NOT EXISTS (re-aplicacao = no-op). Migrations aplicadas sao
--   IMUTAVEIS; mudancas posteriores usam 002_*, 003_* (o runner recusa checksum divergente).
-- Banco: PostgreSQL CONVENCIONAL (sem hypertable/continuous aggregate). Retencao 30h via job.
-- Chave de indicador: surrogate bigserial + value_hash SHA-256 (evita limite de B-tree em
--   URLs longas). value_normalized preservado integralmente (NAO indexado por btree).
-- Seed: separado em infra/seeds/001_cyber_current_environment.sql (dados do ambiente).
-- 11 tabelas criadas: organization, cyber_tenant_config, cyber_indicator,
--   cyber_oat_observation, cyber_workbench_indicator, cyber_workbench_oat_link,
--   cyber_suspicious_object, cyber_suspicious_object_history, cyber_collection_state,
--   cyber_enforcement_capability, cyber_discard_sample.
-- =====================================================================================

-- =====================================================================================
-- EXTENSAO ao cadastro existente (NAO substitui `tenant`)
-- =====================================================================================

-- (1) organization — registro de orgaos (grupo de tenants). Dinamico via seed.
CREATE TABLE IF NOT EXISTS organization (
    organization_id  text        PRIMARY KEY,
    name             text        NOT NULL,
    display_order    integer     NOT NULL DEFAULT 0,
    cyber_enabled    boolean     NOT NULL DEFAULT true,
    enabled          boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- (2) cyber_tenant_config — extensao 1:1 da tabela base `tenant` (reuso, nao duplicacao).
--     Guarda o vinculo tenant->organization e as flags de coleta Cyber. A identidade do
--     tenant continua vindo de `tenant`; aqui so mora a configuracao Cyber.
CREATE TABLE IF NOT EXISTS cyber_tenant_config (
    tenant_id                   text        PRIMARY KEY REFERENCES tenant(tenant_id),
    organization_id             text        NOT NULL REFERENCES organization(organization_id),
    cyber_enabled               boolean     NOT NULL DEFAULT true,
    oat_enabled                 boolean     NOT NULL DEFAULT true,
    workbench_enabled           boolean     NOT NULL DEFAULT true,
    suspicious_objects_enabled  boolean     NOT NULL DEFAULT true,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_tenantcfg_org ON cyber_tenant_config (organization_id);

-- =====================================================================================
-- MODELO CYBER
-- =====================================================================================

-- (3) cyber_indicator — entidade canonica do indicador. Chave surrogate + hash SHA-256.
--     value_hash = sha256( indicator_type || '|' || value_normalized )  (rep. canonica).
--     value_normalized preservado integralmente; NAO ha indice btree sobre ele (URLs longas).
--     Geolocalizacao vive AQUI e so se aplica a indicadores de rede (ip/domain/url).
--     Defesa contra colisao (feita no coletor, no upsert):
--       INSERT ... ON CONFLICT (tenant_id, indicator_type, value_hash)
--       DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at, value_raw=EXCLUDED.value_raw,
--                     updated_at=now()
--       WHERE cyber_indicator.value_normalized = EXCLUDED.value_normalized
--       RETURNING indicator_pk;
--     Se o RETURNING vier vazio (value_normalized divergente para o mesmo hash), o coletor
--     trata como COLISAO/inconsistencia: registra alerta e NAO mescla (nunca sobrescreve).
CREATE TABLE IF NOT EXISTS cyber_indicator (
    indicator_pk          bigserial   PRIMARY KEY,
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_type        text        NOT NULL,
    value_hash            bytea       NOT NULL,   -- SHA-256 (32 bytes) da rep. canonica
    value_normalized      text        NOT NULL,   -- valor canonico COMPLETO (preservado)
    value_raw             text        NOT NULL,
    -- geolocalizacao (apenas para tipos de rede)
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
    CONSTRAINT uq_indicator_hash UNIQUE (tenant_id, indicator_type, value_hash),
    CONSTRAINT ck_indicator_type CHECK (indicator_type IN
        ('ip','domain','url','fileSha1','fileSha256','senderMailAddress')),
    -- garante SHA-256 (32 bytes); rejeita SHA-1 (20 bytes) por design
    CONSTRAINT ck_indicator_hashlen CHECK (octet_length(value_hash) = 32),
    -- geo so existe para indicadores de rede (cobre TODAS as 10 colunas de geo, incl.
    -- geo_resolution_method/geo_resolved_at/geo_expires_at que alimentam o job de frescor)
    CONSTRAINT ck_indicator_geo_scope CHECK (
        indicator_type IN ('ip','domain','url')
        OR (geo_status IS NULL AND geo_resolution_method IS NULL
            AND country IS NULL AND country_iso2 IS NULL AND city IS NULL
            AND latitude IS NULL AND longitude IS NULL AND resolved_ip IS NULL
            AND geo_resolved_at IS NULL AND geo_expires_at IS NULL)),
    CONSTRAINT ck_indicator_geostat CHECK (geo_status IS NULL OR geo_status IN
        ('ok','private','nogeo','unresolved','pending')),
    CONSTRAINT ck_indicator_geomethod CHECK (geo_resolution_method IS NULL OR
        geo_resolution_method IN ('direct_ip','dns','none')),
    CONSTRAINT ck_indicator_lat CHECK (latitude  IS NULL OR (latitude  BETWEEN -90  AND 90)),
    CONSTRAINT ck_indicator_lon CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180))
);
-- indice de pais em cyber_indicator (NAO em cyber_oat_observation)
CREATE INDEX IF NOT EXISTS ix_indicator_country  ON cyber_indicator (country) WHERE country IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_indicator_lastseen ON cyber_indicator (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_indicator_geoexp   ON cyber_indicator (geo_expires_at) WHERE geo_expires_at IS NOT NULL;

-- (4) cyber_oat_observation — fluxo de observacoes do OAT. Referencia indicator_pk.
--     Sem organization_id (deriva via tenant/cyber_tenant_config). Multiplos indicadores
--     por deteccao: mesmo source_event_id com indicator_pk/source_field/indicator_role
--     distintos gera linhas distintas (garantido pelo UNIQUE composto).
CREATE TABLE IF NOT EXISTS cyber_oat_observation (
    observation_id        bigserial   PRIMARY KEY,
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_pk          bigint      NOT NULL REFERENCES cyber_indicator(indicator_pk),
    source                text        NOT NULL,
    product_code          text,
    source_event_id       text        NOT NULL,   -- uuid da detection OAT
    source_field          text        NOT NULL,   -- highlightedObject.field / denyListHost
    indicator_role        text        NOT NULL,   -- attacker / c2 / peer / target ...
    value_raw_observed    text,                    -- forma exata vista nesta ocorrencia (forense)
    event_time            timestamptz NOT NULL,   -- detectionTime (D1)
    ingest_time           timestamptz,
    severity              text        NOT NULL,
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
        (tenant_id, source, source_event_id, indicator_pk, source_field, indicator_role),
    CONSTRAINT ck_oat_severity CHECK (severity IN ('high','critical')),
    CONSTRAINT ck_oat_enforce  CHECK (enforcement_status IN
        ('prevented_confirmed','allowed_confirmed','observed_not_prevented','observed','unknown')),
    CONSTRAINT ck_oat_basis    CHECK (policy_match_basis IN ('event_time','current_state','unavailable'))
);
CREATE INDEX IF NOT EXISTS ix_oat_event      ON cyber_oat_observation (event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_tenant_evt ON cyber_oat_observation (tenant_id, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_enforce    ON cyber_oat_observation (tenant_id, enforcement_status, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_oat_indicator  ON cyber_oat_observation (indicator_pk);
CREATE INDEX IF NOT EXISTS ix_oat_source     ON cyber_oat_observation (tenant_id, source, event_time DESC);

-- (5) cyber_workbench_indicator — indicadores externos de alertas Workbench.
--     PK surrogate + UNIQUE natural por indicator_pk (correcao #3). Referencia indicator_pk.
CREATE TABLE IF NOT EXISTS cyber_workbench_indicator (
    workbench_indicator_pk bigserial   PRIMARY KEY,
    tenant_id              text        NOT NULL REFERENCES tenant(tenant_id),
    indicator_pk           bigint      NOT NULL REFERENCES cyber_indicator(indicator_pk),
    alert_id               text        NOT NULL,   -- WB-xxxx
    indicator_role         text,
    alert_severity         text,
    model                  text,
    provider               text,
    provenance             text[],
    alert_created_at       timestamptz NOT NULL,
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at           timestamptz NOT NULL DEFAULT now(),
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_wb_indicator UNIQUE (tenant_id, alert_id, indicator_pk)
);
CREATE INDEX IF NOT EXISTS ix_wb_tenant_created ON cyber_workbench_indicator (tenant_id, alert_created_at DESC);
CREATE INDEX IF NOT EXISTS ix_wb_indicator      ON cyber_workbench_indicator (indicator_pk);

-- (6) cyber_workbench_oat_link — correlacao M:N Workbench<->OAT (FKs reais, CASCADE).
CREATE TABLE IF NOT EXISTS cyber_workbench_oat_link (
    tenant_id              text        NOT NULL REFERENCES tenant(tenant_id),
    workbench_indicator_pk bigint      NOT NULL
        REFERENCES cyber_workbench_indicator(workbench_indicator_pk) ON DELETE CASCADE,
    oat_observation_id     bigint      NOT NULL
        REFERENCES cyber_oat_observation(observation_id) ON DELETE CASCADE,
    link_method            text        NOT NULL,
    link_confidence        text        NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_wb_oat_link PRIMARY KEY (workbench_indicator_pk, oat_observation_id),
    CONSTRAINT ck_link_confidence CHECK (link_confidence IN ('high','medium','low'))
);
CREATE INDEX IF NOT EXISTS ix_wblink_obs    ON cyber_workbench_oat_link (oat_observation_id);
CREATE INDEX IF NOT EXISTS ix_wblink_tenant ON cyber_workbench_oat_link (tenant_id);

-- (7) cyber_suspicious_object — estado ATUAL da block-list curada (1:1 com um indicador).
CREATE TABLE IF NOT EXISTS cyber_suspicious_object (
    indicator_pk          bigint      PRIMARY KEY REFERENCES cyber_indicator(indicator_pk),
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
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
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_so_active ON cyber_suspicious_object (tenant_id, is_active);

-- (8) cyber_suspicious_object_history — historico temporal do SO (referencia indicator_pk;
--     CHECK de intervalo). Transicao = fecha intervalo atual (valid_to) + insere novo +
--     atualiza cyber_suspicious_object, na MESMA transacao. Primeira sincronizacao completa
--     registra o ESTADO da 1a coleta (valid_from=1a coleta, change_type='added'), sem
--     historico retroativo.
CREATE TABLE IF NOT EXISTS cyber_suspicious_object_history (
    indicator_pk          bigint      NOT NULL REFERENCES cyber_indicator(indicator_pk),
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    valid_from            timestamptz NOT NULL,
    valid_to              timestamptz,
    scan_action           text,
    risk_level            text,
    in_exception_list     boolean,
    change_type           text        NOT NULL,
    policy_match_basis    text        NOT NULL DEFAULT 'current_state',
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_so_history PRIMARY KEY (indicator_pk, valid_from),
    CONSTRAINT ck_soh_change CHECK (change_type IN ('added','modified','removed')),
    CONSTRAINT ck_soh_basis  CHECK (policy_match_basis IN ('event_time','current_state','unavailable')),
    CONSTRAINT ck_soh_interval CHECK (valid_to IS NULL OR valid_to > valid_from)
);
CREATE INDEX IF NOT EXISTS ix_soh_indicator ON cyber_suspicious_object_history (indicator_pk, valid_from DESC);
CREATE INDEX IF NOT EXISTS ix_soh_open      ON cyber_suspicious_object_history (indicator_pk) WHERE valid_to IS NULL;

-- (9) cyber_collection_state — watermark/telemetria por (tenant, collector, source,
--     severity_scope). Watermark = fim do ultimo intervalo contiguo completo (oldest-first,
--     stop-on-gap). status='partial' quando saturado/incompleto.
CREATE TABLE IF NOT EXISTS cyber_collection_state (
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    collector             text        NOT NULL,   -- oat / workbench / suspicious_object
    source                text        NOT NULL DEFAULT 'all',
    severity_scope        text        NOT NULL DEFAULT 'all',
    watermark_event_time  timestamptz,
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

-- (10) cyber_enforcement_capability — capacidade de enforcement por (tenant, source,
--      product_code) com frescor (status/last_seen_at/expires_at).
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

-- (11) cyber_discard_sample — amostras (sanitizadas) de descartes para auditoria.
--      Indice em sampled_at + retencao 30h via job. Limite por tenant e por motivo
--      aplicado na escrita pelo coletor; valores sanitizados (truncados/mascarados).
CREATE TABLE IF NOT EXISTS cyber_discard_sample (
    id                    bigserial   PRIMARY KEY,
    tenant_id             text        NOT NULL REFERENCES tenant(tenant_id),
    collector             text,
    source                text,
    reason                text        NOT NULL,
    indicator_type        text,
    value_sanitized       text,
    source_field          text,
    detail_sanitized      text,
    sampled_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_discard_reason CHECK (reason IN
        ('severity','non_public','role','ambiguity','type','action','duplicate','other'))
);
CREATE INDEX IF NOT EXISTS ix_discard_sampled ON cyber_discard_sample (sampled_at);
CREATE INDEX IF NOT EXISTS ix_discard_tenant  ON cyber_discard_sample (tenant_id, reason, sampled_at DESC);

-- =====================================================================================
-- ROLLBACK (executar manualmente para desfazer ESTA migration). Ordem reversa + CASCADE.
-- NAO remove a tabela base `tenant` nem seus dados (nao pertence a esta migration).
-- Apos o rollback, remova tambem o registro em schema_migrations:
--   DELETE FROM schema_migrations WHERE version='001_cyber_schema';
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
-- DROP TABLE IF EXISTS cyber_tenant_config             CASCADE;
-- DROP TABLE IF EXISTS organization                    CASCADE;
-- DELETE FROM schema_migrations WHERE version='001_cyber_schema';
-- COMMIT;
-- =====================================================================================
