CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE tenant (
    tenant_id      TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    region_base    TEXT NOT NULL DEFAULT 'https://api.xdr.trendmicro.com',
    created_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE asset (
    asset_id       TEXT,
    tenant_id      TEXT REFERENCES tenant,
    hostname       TEXT,
    os_platform    TEXT,
    asset_type     TEXT,
    epp_status     TEXT,
    edr_conn       TEXT,
    risk_score     INT,
    last_seen      TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, asset_id)
);

CREATE TABLE wb_alert (
    alert_id       TEXT,
    tenant_id      TEXT REFERENCES tenant,
    severity       TEXT,
    status         TEXT,
    investigation  TEXT,
    score          INT,
    model          TEXT,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, alert_id, created_at)
);
SELECT create_hypertable('wb_alert','created_at');

CREATE TABLE sec_event (
    event_id       TEXT,
    tenant_id      TEXT REFERENCES tenant,
    source         TEXT,
    severity       TEXT,
    technique_id   TEXT,
    tactic_id      TEXT,
    endpoint_guid  TEXT,
    src_ip         INET,
    dst_ip         INET,
    dst_port       INT,
    verdict        TEXT,
    detected_at    TIMESTAMPTZ NOT NULL,
    raw            JSONB,
    PRIMARY KEY (tenant_id, event_id, detected_at)
);
SELECT create_hypertable('sec_event','detected_at');
CREATE INDEX ix_event_tactic ON sec_event (tenant_id, tactic_id, detected_at DESC);
CREATE INDEX ix_event_source ON sec_event (tenant_id, source, detected_at DESC);

CREATE TABLE posture_snapshot (
    tenant_id      TEXT REFERENCES tenant,
    captured_at    TIMESTAMPTZ NOT NULL,
    risk_index     INT,
    exposure_lvl   TEXT,
    attack_lvl     TEXT,
    config_lvl     TEXT,
    cve_total      INT,
    PRIMARY KEY (tenant_id, captured_at)
);
SELECT create_hypertable('posture_snapshot','captured_at');

CREATE TABLE vulnerability (
    tenant_id      TEXT REFERENCES tenant,
    cve_id         TEXT,
    cvss           NUMERIC(3,1),
    severity       TEXT,
    affected_count INT,
    captured_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cve_id, captured_at)
);

CREATE TABLE attack_geo (
    tenant_id      TEXT REFERENCES tenant,
    event_id       TEXT,
    src_country    TEXT,
    src_city       TEXT,
    src_lat        NUMERIC(8,4),
    src_lon        NUMERIC(8,4),
    dst_country    TEXT,
    dst_lat        NUMERIC(8,4),
    dst_lon        NUMERIC(8,4),
    threat_type    TEXT,
    severity       TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id, occurred_at)
);
SELECT create_hypertable('attack_geo','occurred_at');

CREATE MATERIALIZED VIEW sec_event_hourly
WITH (timescaledb.continuous) AS
SELECT tenant_id, source, severity,
       time_bucket('1 hour', detected_at) AS bucket,
       count(*) AS n
FROM sec_event
GROUP BY tenant_id, source, severity, bucket;

SELECT add_continuous_aggregate_policy('sec_event_hourly',
  start_offset => INTERVAL '30 days',
  end_offset   => INTERVAL '1 hour',
  schedule_interval => INTERVAL '5 minutes');

SELECT add_retention_policy('sec_event', INTERVAL '30 days');

INSERT INTO tenant (tenant_id, display_name) VALUES
    ('prodesp-sp', 'Prodesp')
ON CONFLICT (tenant_id) DO NOTHING;
