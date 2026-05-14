-- =====================================================================
-- MERIDIAN · Network Intelligence Platform
-- PostgreSQL schema · version 1.0.0 · 2026-04-18
-- =====================================================================
-- Target: PostgreSQL 15+ on Debian 12.
-- This is the fresh-install schema. Migrations (if any) live in
-- db/migrations/ as numbered incremental diffs.
-- =====================================================================

-- =====================================================================
-- 0 · EXTENSIONS
-- =====================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid, crypt()
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- fast ILIKE / search
CREATE EXTENSION IF NOT EXISTS citext;       -- case-insensitive text (emails, usernames)
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- GIN on scalar + array combined indexes

-- =====================================================================
-- 1 · ENUMS
-- =====================================================================
CREATE TYPE user_role              AS ENUM ('super_admin','admin','analyst','viewer','auditor','api_service');
CREATE TYPE auth_method            AS ENUM ('credential','sso_oidc','sso_saml','ldap','api_token');
CREATE TYPE scope_visibility       AS ENUM ('internal','external','both');
CREATE TYPE approval_state         AS ENUM ('pending','approved','denied','expired','cancelled');
CREATE TYPE cert_type              AS ENUM ('portal','monitored','client_mtls','internal');
CREATE TYPE cert_key_type          AS ENUM ('rsa2048','rsa3072','rsa4096','ecdsa_p256','ecdsa_p384','ed25519');
CREATE TYPE cert_challenge_type    AS ENUM ('http_01','dns_01','tls_alpn_01','manual_csr');
CREATE TYPE vuln_status            AS ENUM ('open','fixed','suppressed','accepted_risk','false_positive');
CREATE TYPE vuln_severity          AS ENUM ('critical','high','medium','low','info');
CREATE TYPE notif_channel_type     AS ENUM ('email','sms_twilio','sms_gateway','slack','teams','webhook','inapp','pagerduty');
CREATE TYPE monitor_type           AS ENUM ('http','https','port_tcp','port_udp','ping_icmp','cert_expiry','dns_record','tls_grade');
CREATE TYPE monitor_status         AS ENUM ('ok','warn','down','unknown','muted');
CREATE TYPE job_kind               AS ENUM ('system','user','on_event');
CREATE TYPE wizard_outcome         AS ENUM ('ok','warn','fail','cancelled','error');
CREATE TYPE secret_category        AS ENUM ('api_key','password','ssh_key','certificate','token','other');
CREATE TYPE directory_type         AS ENUM (
  'active_directory','entra_id','ldap_generic',
  'samba_ad_dc','freeipa','ds_389','openldap','jumpcloud'
);
CREATE TYPE threat_intel_kind      AS ENUM ('abuseipdb','greynoise','virustotal','urlscan','shodan','censys');
CREATE TYPE theme_choice           AS ENUM ('dark','midnight','light','high_contrast');
CREATE TYPE message_channel        AS ENUM ('direct','group','broadcast');
CREATE TYPE webhook_direction      AS ENUM ('inbound','outbound');

-- =====================================================================
-- 2 · HELPER FUNCTIONS & TRIGGERS
-- =====================================================================
CREATE OR REPLACE FUNCTION fn_touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply via: CREATE TRIGGER tg_<table>_touch BEFORE UPDATE ON <table> FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 3 · IDENTITY · users, groups, permissions
-- =====================================================================
CREATE TABLE users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username            CITEXT UNIQUE NOT NULL,
  email               CITEXT UNIQUE NOT NULL,
  display_name        TEXT,
  password_hash       TEXT,                       -- NULL when auth_method != credential
  password_changed_at TIMESTAMPTZ,                 -- drives expiry + forced-rotation reminders
  primary_auth        auth_method NOT NULL DEFAULT 'credential',
  role                user_role   NOT NULL DEFAULT 'viewer',
  enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
  locked              BOOLEAN     NOT NULL DEFAULT FALSE,
  failed_login_count  INTEGER     NOT NULL DEFAULT 0,
  mfa_enrolled        BOOLEAN     NOT NULL DEFAULT FALSE,
  mfa_secret_enc      BYTEA,                      -- encrypted TOTP seed
  phone_e164          TEXT,
  sms_carrier_gateway TEXT,                       -- e.g. 'vtext.com' for AT&T email-to-SMS
  avatar_path         TEXT,
  timezone            TEXT        NOT NULL DEFAULT 'UTC',
  preferences         JSONB       NOT NULL DEFAULT '{}'::jsonb,
  external_id         TEXT,                       -- subject from OIDC/SAML or DN from LDAP
  max_concurrent_sessions INTEGER NOT NULL DEFAULT 1,  -- anti-sharing policy; raise for legit multi-device users
  idle_timeout_override_min INTEGER,                   -- NULL = follow global default from branding
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at       TIMESTAMPTZ,
  last_active_at      TIMESTAMPTZ,
  deleted_at          TIMESTAMPTZ                  -- soft delete
);
CREATE INDEX ix_users_role_enabled ON users (role, enabled) WHERE deleted_at IS NULL;
CREATE INDEX ix_users_external_id  ON users (external_id) WHERE external_id IS NOT NULL;
CREATE TRIGGER tg_users_touch BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE groups (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT UNIQUE NOT NULL,
  description  TEXT,
  is_system    BOOLEAN NOT NULL DEFAULT FALSE,   -- ddi-ssh, admins, etc.
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_groups_touch BEFORE UPDATE ON groups FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE user_groups (
  user_id    UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  added_by   UUID REFERENCES users(id),
  PRIMARY KEY (user_id, group_id)
);

CREATE TABLE permissions (
  key          TEXT PRIMARY KEY,                  -- e.g. 'dns.sandbox', 'ad.user.reset_password'
  description  TEXT NOT NULL,
  category     TEXT NOT NULL,                     -- 'dns', 'network', 'ad', 'admin', etc.
  requires_two_person BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
  role        user_role NOT NULL,
  permission  TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
  PRIMARY KEY (role, permission)
);

CREATE TABLE group_permissions (
  group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  permission  TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by  UUID REFERENCES users(id),
  PRIMARY KEY (group_id, permission)
);

CREATE TABLE user_permissions (
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission  TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
  allow       BOOLEAN NOT NULL DEFAULT TRUE,      -- allow=FALSE explicitly revokes
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by  UUID REFERENCES users(id),
  expires_at  TIMESTAMPTZ,
  PRIMARY KEY (user_id, permission)
);

-- =====================================================================
-- 4 · AUTH · sessions, tokens, MFA, SSO, AUP, impersonation
-- =====================================================================
CREATE TABLE sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash      TEXT NOT NULL UNIQUE,            -- sha256 of opaque session token
  auth_method     auth_method NOT NULL,
  ip              INET,
  user_agent      TEXT,
  device_label    TEXT,                            -- "iPhone · Safari", derived
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  revoked_by      UUID REFERENCES users(id),
  revoked_reason  TEXT
);
CREATE INDEX ix_sessions_user_active ON sessions (user_id, last_active_at DESC) WHERE revoked_at IS NULL;

CREATE TABLE api_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  token_hash      TEXT NOT NULL UNIQUE,
  scopes          TEXT[] NOT NULL DEFAULT '{}',    -- array of permission keys
  rate_limit_per_min INTEGER NOT NULL DEFAULT 120,
  bound_client_cert_id UUID,                       -- FK set after certificates table
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,
  last_used_at    TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  UNIQUE (user_id, name)
);

CREATE TABLE api_token_usage (
  token_id    UUID NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
  window_start TIMESTAMPTZ NOT NULL,               -- truncated to the minute
  request_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (token_id, window_start)
);

CREATE TABLE mfa_backup_codes (
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash    TEXT NOT NULL,
  used_at      TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE sso_providers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL,                     -- 'oidc','saml','ldap'
  name          TEXT NOT NULL,                     -- "Acme Azure AD"
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  config        JSONB NOT NULL,                    -- issuer, client_id, sso_url, etc.
  secret_id     UUID,                              -- secrets.id; FK set below
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_sso_touch BEFORE UPDATE ON sso_providers FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE login_attempts (
  id           BIGSERIAL PRIMARY KEY,
  username     CITEXT,                             -- may be unknown
  ip           INET,
  success      BOOLEAN NOT NULL,
  mfa_used     BOOLEAN NOT NULL DEFAULT FALSE,
  reason       TEXT,                               -- 'bad_password','locked','mfa_required','ok', etc.
  ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_agent   TEXT
);
CREATE INDEX ix_login_attempts_ip_ts    ON login_attempts (ip, ts DESC);
CREATE INDEX ix_login_attempts_user_ts  ON login_attempts (username, ts DESC);

CREATE TABLE aup_versions (
  id          SERIAL PRIMARY KEY,
  body        TEXT NOT NULL,
  published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_by UUID REFERENCES users(id),
  active      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE aup_acceptances (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  aup_version INTEGER NOT NULL REFERENCES aup_versions(id),
  accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          INET,
  user_agent  TEXT,
  UNIQUE (user_id, aup_version)
);

CREATE TABLE impersonations (
  id            BIGSERIAL PRIMARY KEY,
  admin_id      UUID NOT NULL REFERENCES users(id),
  target_id     UUID NOT NULL REFERENCES users(id),
  reason        TEXT NOT NULL,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,
  approval_id   UUID                               -- FK set below
);

-- =====================================================================
-- 5 · CONFIG · branding, generic KV
-- =====================================================================
CREATE TABLE branding (
  id                         INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- single row
  display_name               TEXT NOT NULL DEFAULT 'Meridian',
  short_name                 TEXT NOT NULL DEFAULT 'Meridian',
  support_email              TEXT,
  support_url                TEXT,
  privacy_url                TEXT,
  imprint_url                TEXT,
  default_timezone           TEXT NOT NULL DEFAULT 'UTC',
  date_format                TEXT NOT NULL DEFAULT 'iso',
  logo_path                  TEXT,
  favicon_path               TEXT,
  login_bg_path              TEXT,
  pdf_header_path            TEXT,
  theme                      theme_choice NOT NULL DEFAULT 'dark',
  accent_hex                 TEXT NOT NULL DEFAULT '#20c896',
  pre_login_warning          TEXT,
  aup_require_first_login    BOOLEAN NOT NULL DEFAULT TRUE,
  aup_reprompt_on_change     BOOLEAN NOT NULL DEFAULT TRUE,
  aup_show_footer_link       BOOLEAN NOT NULL DEFAULT TRUE,
  email_from_name            TEXT,
  email_from_address         TEXT,
  email_signature            TEXT,
  slack_sender_name          TEXT,
  teams_sender_name          TEXT,
  sms_sender_identity        TEXT,
  pdf_footer_text            TEXT,
  pdf_watermark              BOOLEAN NOT NULL DEFAULT FALSE,
  ssh_motd                   TEXT,
  ssh_motd_on_every_login    BOOLEAN NOT NULL DEFAULT TRUE,
  session_idle_timeout_default_min INTEGER NOT NULL DEFAULT 30,
  session_idle_timeout_max_min     INTEGER NOT NULL DEFAULT 1440,
  session_idle_timeout_options     INTEGER[] NOT NULL DEFAULT ARRAY[10,30,60,120,0],  -- 0 = Never
  session_idle_never_allowed       BOOLEAN NOT NULL DEFAULT FALSE,
  session_idle_custom_allowed      BOOLEAN NOT NULL DEFAULT TRUE,
  logo_click_url             TEXT NOT NULL DEFAULT 'https://meridiannip.com',
  logo_click_target          TEXT NOT NULL DEFAULT '_blank',  -- '_blank' or '_self'
  vendor_attribution_hidden  BOOLEAN NOT NULL DEFAULT FALSE,  -- enterprise-only
  updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by                 UUID REFERENCES users(id)
);
CREATE TRIGGER tg_branding_touch BEFORE UPDATE ON branding FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- license / license_activations / license_verifications / license_revocations
-- tables removed 2026-05-13 when Meridian moved to Apache 2.0. See
-- db/migrations/0014_drop_license_subsystem.sql for the drop logic
-- applied to upgraded databases.

CREATE TABLE config_kv (
  key         TEXT PRIMARY KEY,
  value       JSONB NOT NULL,
  description TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by  UUID REFERENCES users(id)
);
CREATE TRIGGER tg_config_kv_touch BEFORE UPDATE ON config_kv FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 6 · TAGS · attach to any entity
-- =====================================================================
CREATE TABLE tags (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        CITEXT NOT NULL,
  color_hex   TEXT NOT NULL DEFAULT '#20c896',
  description TEXT,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name)
);

CREATE TABLE tag_assignments (
  tag_id      UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,                       -- 'domain','ip','host','subnet','cert','monitor', ...
  entity_key  TEXT NOT NULL,                       -- free-form key (e.g. 'example.com' or UUID)
  tagged_by   UUID REFERENCES users(id),
  tagged_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tag_id, entity_type, entity_key)
);
CREATE INDEX ix_tag_assignments_entity ON tag_assignments (entity_type, entity_key);

-- Entity annotations (persistent notes that follow a domain/IP across tools)
CREATE TABLE annotations (
  id          BIGSERIAL PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_key  TEXT NOT NULL,
  body        TEXT NOT NULL,
  author_id   UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_annotations_entity ON annotations (entity_type, entity_key, created_at DESC);
CREATE TRIGGER tg_annotations_touch BEFORE UPDATE ON annotations FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 7 · AUDIT + APPROVALS (two-person gating)
-- =====================================================================
CREATE TABLE audit_events (
  id              BIGSERIAL PRIMARY KEY,
  ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id         UUID REFERENCES users(id),
  impersonator_id UUID REFERENCES users(id),
  action          TEXT NOT NULL,                  -- 'ad.user.reset_password', 'cert.revoke', ...
  target_type     TEXT,
  target_key      TEXT,
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip              INET,
  user_agent      TEXT,
  justification   TEXT,
  approval_id     UUID,                            -- FK to approvals, set when action was gated
  outcome         TEXT NOT NULL DEFAULT 'ok'       -- 'ok','denied','error'
);
CREATE INDEX ix_audit_ts       ON audit_events (ts DESC);
CREATE INDEX ix_audit_user_ts  ON audit_events (user_id, ts DESC);
CREATE INDEX ix_audit_action   ON audit_events (action, ts DESC);
CREATE INDEX ix_audit_target   ON audit_events (target_type, target_key, ts DESC);

CREATE TABLE approvals (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by   UUID NOT NULL REFERENCES users(id),
  approver_id    UUID REFERENCES users(id),
  action         TEXT NOT NULL,
  target_type    TEXT,
  target_key     TEXT,
  payload        JSONB NOT NULL DEFAULT '{}'::jsonb,
  justification  TEXT NOT NULL,
  state          approval_state NOT NULL DEFAULT 'pending',
  requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at     TIMESTAMPTZ,
  expires_at     TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours',
  decision_note  TEXT
);
CREATE INDEX ix_approvals_pending ON approvals (state, expires_at) WHERE state = 'pending';

ALTER TABLE audit_events     ADD CONSTRAINT fk_audit_approval     FOREIGN KEY (approval_id)     REFERENCES approvals(id);
ALTER TABLE impersonations   ADD CONSTRAINT fk_imp_approval       FOREIGN KEY (approval_id)     REFERENCES approvals(id);

-- CAB / change-freeze windows (block destructive actions)
CREATE TABLE cab_windows (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  description  TEXT,
  starts_at    TIMESTAMPTZ NOT NULL,
  ends_at      TIMESTAMPTZ NOT NULL,
  blocks       TEXT[] NOT NULL DEFAULT '{}',       -- action keys blocked during window
  created_by   UUID REFERENCES users(id),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_cab_window_time ON cab_windows (starts_at, ends_at);

-- =====================================================================
-- 8 · SECRETS VAULT (encrypted-at-rest API keys, bind passwords, etc.)
-- =====================================================================
CREATE TABLE secrets (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT NOT NULL,
  category       secret_category NOT NULL,
  description    TEXT,
  ciphertext     BYTEA NOT NULL,                   -- AES-GCM ciphertext
  nonce          BYTEA NOT NULL,
  key_version    INTEGER NOT NULL DEFAULT 1,       -- rotation-aware
  owner_scope    TEXT,                              -- 'system','user:<id>','group:<id>'
  owner_id       UUID,
  rotation_due   TIMESTAMPTZ,
  last_accessed  TIMESTAMPTZ,
  access_count   BIGINT NOT NULL DEFAULT 0,
  created_by     UUID REFERENCES users(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name, owner_scope, owner_id)
);
CREATE TRIGGER tg_secrets_touch BEFORE UPDATE ON secrets FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

ALTER TABLE sso_providers ADD CONSTRAINT fk_sso_secret FOREIGN KEY (secret_id) REFERENCES secrets(id);

-- =====================================================================
-- 9 · DIRECTORY INTEGRATIONS (AD, Entra, LDAP)
-- =====================================================================
CREATE TABLE directory_integrations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            directory_type NOT NULL,
  name            TEXT NOT NULL,                    -- 'CORP.LOCAL'
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  fqdn            TEXT,
  netbios_name    TEXT,
  primary_uri     TEXT,                             -- ldaps://dc01.corp.local:636
  fallback_uri    TEXT,
  base_dn         TEXT,
  bind_account    TEXT,
  bind_secret_id  UUID REFERENCES secrets(id),
  auth_method     TEXT NOT NULL DEFAULT 'password', -- password|gmsa|keytab|mtls|api_token
  ca_cert_path    TEXT,
  query_timeout_s INTEGER NOT NULL DEFAULT 10,
  last_tested_at  TIMESTAMPTZ,
  last_test_ok    BOOLEAN,
  last_test_error TEXT,
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_dir_touch BEFORE UPDATE ON directory_integrations FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- Threat-intel external-API credentials (one row per configured key).
CREATE TABLE threat_intel_integrations (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind              threat_intel_kind NOT NULL,
  name              TEXT NOT NULL,                    -- 'abuseipdb-prod', 'my-shodan-key'
  enabled           BOOLEAN NOT NULL DEFAULT TRUE,
  api_key_secret_id UUID REFERENCES secrets(id),
  last_tested_at    TIMESTAMPTZ,
  last_test_ok      BOOLEAN,
  last_test_error   TEXT,
  config            JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_ti_touch BEFORE UPDATE ON threat_intel_integrations FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();
CREATE INDEX ix_ti_kind_enabled ON threat_intel_integrations (kind) WHERE enabled;

-- External log collectors. Admin UI caps insert count at 3; schema
-- leaves it open so rolling a destination doesn't require a delete.
CREATE TABLE log_shipping_destinations (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name                TEXT NOT NULL,
  kind                TEXT NOT NULL,                -- syslog|splunk_hec|elastic|cef
  enabled             BOOLEAN NOT NULL DEFAULT TRUE,
  endpoint            TEXT NOT NULL,
  transport           TEXT NOT NULL DEFAULT 'tcp',  -- tcp|udp|tls|https
  facility            TEXT,                         -- syslog facility
  index_or_sourcetype TEXT,
  auth_secret_id      UUID REFERENCES secrets(id),
  ca_cert_path        TEXT,
  event_filter        JSONB NOT NULL DEFAULT '[]'::jsonb,
  batch_size          INTEGER NOT NULL DEFAULT 100,
  flush_interval_s    INTEGER NOT NULL DEFAULT 10,
  last_shipped_at     TIMESTAMPTZ,
  last_cursor_ts      TIMESTAMPTZ,
  last_error          TEXT,
  events_shipped_total INTEGER NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_logship_touch BEFORE UPDATE ON log_shipping_destinations
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- SNMP exposure — community strings + allowed source CIDRs for external
-- monitoring systems (Zabbix/Nagios/PRTG/SolarWinds) polling Meridian's
-- own health. `community` is RO by default; a separate row with
-- `access='rw'` can be added when a monitoring tool needs to clear
-- counters or toggle maintenance mode. SNMPv3 fields stubbed for later.
CREATE TABLE snmp_communities (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,                  -- display label
  access          TEXT NOT NULL DEFAULT 'ro',     -- 'ro' | 'rw'
  community       TEXT NOT NULL,                  -- v2c community string (secret)
  allowed_sources TEXT[] NOT NULL DEFAULT '{}',   -- CIDR allow-list; empty = any
  v3_user         TEXT,                           -- SNMPv3 username (future)
  v3_auth_key     TEXT,                           -- v3 auth passphrase (vault id later)
  v3_priv_key     TEXT,                           -- v3 priv passphrase
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE snmp_communities OWNER TO meridian;
CREATE TRIGGER tg_snmp_touch BEFORE UPDATE ON snmp_communities
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- User-editable bookmarks. Global rows visible to all; user rows only
-- to the owner. Per-user ordering of the combined list lives on
-- users.preferences.link_order, not on the link row itself.
CREATE TABLE important_links (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope       TEXT NOT NULL CHECK (scope IN ('global','user')),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  url         TEXT NOT NULL,
  description TEXT,
  category    TEXT,
  sort_order  INTEGER NOT NULL DEFAULT 100,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((scope = 'global' AND user_id IS NULL)
      OR (scope = 'user'   AND user_id IS NOT NULL))
);
CREATE INDEX ix_links_scope_user ON important_links (scope, user_id);
CREATE TRIGGER tg_links_touch BEFORE UPDATE ON important_links
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- Track which password-expiry thresholds each user has been notified of
-- in the current password cycle. A row per (user_id, days_threshold)
-- prevents the same reminder firing every beat-tick for a week straight.
-- The nightly password-expiry task deletes rows whose cycle is newer
-- than the notification so a fresh rotation restarts the sequence.
CREATE TABLE password_expiry_notifications (
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  days_threshold      INTEGER NOT NULL,           -- 15|10|5|4|3|2|1
  cycle_started_at    TIMESTAMPTZ NOT NULL,       -- user.password_changed_at at fire time
  notified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, days_threshold, cycle_started_at)
);
CREATE INDEX ix_pwd_expiry_cycle ON password_expiry_notifications (user_id, cycle_started_at);

-- Catalog of Threat-Intel sources (tabs on /ui/threat-intel). Every
-- built-in provider is seeded here at install time. Toggling `enabled`
-- hides the tab; `config` carries per-source overrides (base_url,
-- timeout_s, auth_header) that admins can tweak without a code deploy
-- when an upstream provider changes their URL or auth scheme.
CREATE TABLE threat_intel_sources (
  source_key    TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  category      TEXT NOT NULL,                     -- vulnerability|reputation|exposure
  requires_key  BOOLEAN NOT NULL DEFAULT FALSE,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  config        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_ti_src_touch BEFORE UPDATE ON threat_intel_sources FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

INSERT INTO threat_intel_sources (source_key, display_name, category, requires_key) VALUES
  ('cve_nvd',    'CVE (NVD)',        'vulnerability', FALSE),
  ('kev',        'CISA KEV',         'vulnerability', FALSE),
  ('epss',       'EPSS',             'vulnerability', FALSE),
  ('circl',      'CIRCL',            'vulnerability', FALSE),
  ('ip_rep',     'IP reputation',    'reputation',    FALSE),
  ('dshield',    'DShield',          'reputation',    FALSE),
  ('abuseipdb',  'AbuseIPDB',        'reputation',    TRUE),
  ('greynoise',  'GreyNoise',        'reputation',    TRUE),
  ('virustotal', 'VirusTotal',       'reputation',    TRUE),
  ('urlscan',    'URLScan.io',       'reputation',    TRUE),
  ('shodan',     'Shodan',           'exposure',      TRUE),
  ('censys',     'Censys',           'exposure',      TRUE)
ON CONFLICT (source_key) DO NOTHING;

-- =====================================================================
-- 10 · (removed) DHCP / IPAM source configs
-- Meridian no longer hosts DDI state. Commercial installs are expected
-- to bring their own system of record; the app only provides DNS /
-- monitoring / directory tooling. The tables dhcp_sources, ipam_sources,
-- and ipam_conflicts were dropped; their backend enum types were also
-- removed from the enum section above.
-- =====================================================================

-- =====================================================================
-- 11 · QUERIES · presets, history, DNS change baselines
-- =====================================================================
CREATE TABLE query_presets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id),          -- NULL = shared preset (admin-created)
  name        TEXT NOT NULL,
  tool        TEXT NOT NULL,                      -- 'dig','propagation','ping', ...
  payload     JSONB NOT NULL,
  shared      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_qpresets_touch BEFORE UPDATE ON query_presets FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE query_history (
  id           BIGSERIAL PRIMARY KEY,
  user_id      UUID NOT NULL REFERENCES users(id),
  tool         TEXT NOT NULL,
  target       TEXT,
  input        JSONB NOT NULL DEFAULT '{}'::jsonb,
  result       JSONB,
  result_hash  TEXT,                               -- sha256 for diff detection
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  duration_ms  INTEGER,
  status       TEXT NOT NULL DEFAULT 'ok',
  error        TEXT,
  pinned       BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_qh_user_time ON query_history (user_id, started_at DESC);
CREATE INDEX ix_qh_target    ON query_history (target, started_at DESC);
CREATE INDEX ix_qh_tool      ON query_history (tool, started_at DESC);

CREATE TABLE dns_change_baselines (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain       TEXT NOT NULL,
  record_type  TEXT,
  snapshot     JSONB NOT NULL,
  snapshot_hash TEXT NOT NULL,
  baseline_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   UUID REFERENCES users(id),
  UNIQUE (domain, record_type, baseline_at)
);

-- =====================================================================
-- 12 · MONITORS (ping, port, http, cert, dns)
-- =====================================================================
CREATE TABLE monitors (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id          UUID REFERENCES users(id),
  name              TEXT NOT NULL,
  kind              monitor_type NOT NULL,
  target            TEXT NOT NULL,                -- URL, host, host:port, domain
  interval_seconds  INTEGER NOT NULL DEFAULT 60,
  timeout_seconds   INTEGER NOT NULL DEFAULT 10,
  config            JSONB NOT NULL DEFAULT '{}'::jsonb,   -- thresholds, expected codes, etc.
  notify_channels   UUID[] NOT NULL DEFAULT '{}',
  enabled           BOOLEAN NOT NULL DEFAULT TRUE,
  last_status       monitor_status,
  last_sample_at    TIMESTAMPTZ,
  last_value        DOUBLE PRECISION,
  consecutive_fails INTEGER NOT NULL DEFAULT 0,
  scope             scope_visibility NOT NULL DEFAULT 'both',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_monitors_enabled ON monitors (enabled, kind);
CREATE TRIGGER tg_monitors_touch BEFORE UPDATE ON monitors FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- Raw samples (retention-managed; consider partitioning by month in prod).
CREATE TABLE monitor_samples (
  monitor_id  UUID NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  ts          TIMESTAMPTZ NOT NULL,
  status      monitor_status NOT NULL,
  value       DOUBLE PRECISION,
  detail      JSONB,
  PRIMARY KEY (monitor_id, ts)
);
CREATE INDEX ix_samples_ts ON monitor_samples (ts DESC);

CREATE TABLE monitor_rollups_5m (
  monitor_id  UUID NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  bucket      TIMESTAMPTZ NOT NULL,                -- truncated to 5m
  samples     INTEGER NOT NULL,
  ok_count    INTEGER NOT NULL,
  warn_count  INTEGER NOT NULL,
  down_count  INTEGER NOT NULL,
  avg_value   DOUBLE PRECISION,
  p95_value   DOUBLE PRECISION,
  PRIMARY KEY (monitor_id, bucket)
);

CREATE TABLE monitor_rollups_1h (
  monitor_id  UUID NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  bucket      TIMESTAMPTZ NOT NULL,
  samples     INTEGER NOT NULL,
  ok_count    INTEGER NOT NULL,
  warn_count  INTEGER NOT NULL,
  down_count  INTEGER NOT NULL,
  avg_value   DOUBLE PRECISION,
  p95_value   DOUBLE PRECISION,
  PRIMARY KEY (monitor_id, bucket)
);

CREATE TABLE monitor_incidents (
  id           BIGSERIAL PRIMARY KEY,
  monitor_id   UUID NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  opened_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at    TIMESTAMPTZ,
  severity     monitor_status NOT NULL,
  detail       JSONB,
  acked_by     UUID REFERENCES users(id),
  acked_at     TIMESTAMPTZ
);
CREATE INDEX ix_incidents_open ON monitor_incidents (monitor_id) WHERE closed_at IS NULL;

-- =====================================================================
-- 13 · WIZARDS
-- =====================================================================
CREATE TABLE wizards (
  key         TEXT PRIMARY KEY,                    -- 'dns.resolve_fail','mail.delivery','ssl.deep_inspect'
  category    TEXT NOT NULL,                       -- 'ddi','network'
  name        TEXT NOT NULL,
  description TEXT,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  scope       scope_visibility NOT NULL DEFAULT 'both',
  config      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE wizard_runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wizard_key   TEXT NOT NULL REFERENCES wizards(key),
  user_id      UUID NOT NULL REFERENCES users(id),
  target       TEXT,
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  outcome      wizard_outcome,
  steps        JSONB NOT NULL DEFAULT '[]'::jsonb,
  findings     JSONB NOT NULL DEFAULT '[]'::jsonb,
  suggestions  JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ranked probable causes + actions
  ticket_ref   TEXT
);
CREATE INDEX ix_wiz_runs_user_time ON wizard_runs (user_id, started_at DESC);
CREATE INDEX ix_wiz_runs_target    ON wizard_runs (target, started_at DESC);

-- =====================================================================
-- 14 · RUNBOOKS / PLAYBOOKS (chain tools into named workflows)
-- =====================================================================
CREATE TABLE runbooks (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  description  TEXT,
  owner_id     UUID REFERENCES users(id),
  owner_group  UUID REFERENCES groups(id),
  shared       BOOLEAN NOT NULL DEFAULT FALSE,
  steps        JSONB NOT NULL,                     -- ordered list of {tool, params, continue_on}
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_runbooks_touch BEFORE UPDATE ON runbooks FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE runbook_runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  runbook_id   UUID NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
  user_id      UUID NOT NULL REFERENCES users(id),
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'running',
  step_results JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- =====================================================================
-- 15 · FILE REPO (per-user uploads: scripts, docs, pcaps, reports)
-- =====================================================================
CREATE TABLE files (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename      TEXT NOT NULL,
  mime_type     TEXT,
  size_bytes    BIGINT NOT NULL,
  sha256_hex    TEXT NOT NULL,
  storage_path  TEXT NOT NULL,
  pinned        BOOLEAN NOT NULL DEFAULT FALSE,
  category      TEXT,                              -- 'script','doc','pcap','export','avatar','upload'
  encrypted     BOOLEAN NOT NULL DEFAULT FALSE,
  tags          TEXT[] NOT NULL DEFAULT '{}',
  uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ,                       -- nullable, for auto-cleanup
  virus_scan    TEXT                               -- 'clean','infected','unscanned','skipped'
);
CREATE INDEX ix_files_owner ON files (owner_id, uploaded_at DESC);
CREATE INDEX ix_files_expiry ON files (expires_at) WHERE expires_at IS NOT NULL;

-- =====================================================================
-- 16 · MESSAGING (inter-user messages + admin broadcasts)
-- =====================================================================
CREATE TABLE messages (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  channel      message_channel NOT NULL,
  from_user    UUID REFERENCES users(id),
  to_user      UUID REFERENCES users(id),
  to_group     UUID REFERENCES groups(id),
  subject      TEXT,
  body         TEXT NOT NULL,
  attachments  UUID[] NOT NULL DEFAULT '{}',       -- file ids
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  priority     TEXT NOT NULL DEFAULT 'normal'      -- 'low','normal','high','urgent'
);
CREATE INDEX ix_msgs_to_user ON messages (to_user, created_at DESC);
CREATE INDEX ix_msgs_to_group ON messages (to_group, created_at DESC);

CREATE TABLE message_reads (
  message_id  UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  read_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);

-- =====================================================================
-- 17 · NOTIFICATIONS
-- =====================================================================
CREATE TABLE notif_channels (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID REFERENCES users(id),          -- NULL = global (admin-managed)
  kind          notif_channel_type NOT NULL,
  target        TEXT NOT NULL,                      -- email addr, webhook URL, phone #, etc.
  description   TEXT NOT NULL,                      -- matches UI rule: every toggle has a description
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  config        JSONB NOT NULL DEFAULT '{}'::jsonb,
  secret_id     UUID REFERENCES secrets(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_notif_ch_touch BEFORE UPDATE ON notif_channels FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE notif_deliveries (
  id           BIGSERIAL PRIMARY KEY,
  channel_id   UUID NOT NULL REFERENCES notif_channels(id) ON DELETE CASCADE,
  subject      TEXT,
  body         TEXT,
  payload      JSONB,
  sent_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  status       TEXT NOT NULL,                      -- 'sent','failed','deferred'
  error        TEXT,
  attempt      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX ix_notif_del_channel_time ON notif_deliveries (channel_id, sent_at DESC);

-- =====================================================================
-- 18 · SCHEDULED JOBS
-- =====================================================================
CREATE TABLE jobs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL UNIQUE,
  description     TEXT NOT NULL,                   -- matches UI rule: every toggle has a description
  kind            job_kind NOT NULL DEFAULT 'system',
  cron_expression TEXT,                            -- NULL if kind='on_event'
  handler         TEXT NOT NULL,                   -- Python dotted path
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  owner_id        UUID REFERENCES users(id),
  notify_channels UUID[] NOT NULL DEFAULT '{}',
  respects_cab    BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at     TIMESTAMPTZ,
  last_run_status TEXT,
  last_run_output TEXT,
  next_run_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_jobs_touch BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE job_runs (
  id           BIGSERIAL PRIMARY KEY,
  job_id       UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'running',
  output       TEXT,
  error        TEXT,
  stats        JSONB
);
CREATE INDEX ix_jobruns_job_time ON job_runs (job_id, started_at DESC);

-- Scope rules · admin-editable CIDR allow/deny on top of the RFC1918 defaults.
-- Consulted by network.scope.check() before any tool dispatches a probe.
-- kind values:
--   'internal_extra'  — CIDR counts as "internal" even if not RFC1918 (e.g. 100.64/10 CGNAT)
--   'external_extra'  — CIDR counts as "external" even if RFC1918 (e.g. a NAT'd partner range)
--   'deny'            — portal must NEVER probe this CIDR, regardless of scope
CREATE TABLE scope_rules (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         TEXT NOT NULL CHECK (kind IN ('internal_extra','external_extra','deny')),
  cidr         CIDR NOT NULL,
  note         TEXT,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   UUID REFERENCES users(id),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, cidr)
);
CREATE INDEX ix_scope_rules_kind ON scope_rules (kind) WHERE enabled;
CREATE TRIGGER tg_scope_rules_touch BEFORE UPDATE ON scope_rules FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- Retention rules (what each cleanup job uses as its policy)
CREATE TABLE retention_rules (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope        TEXT NOT NULL UNIQUE,                -- 'audit_events','query_history','file_repo', etc.
  description  TEXT NOT NULL,
  keep_days    INTEGER,
  keep_count   INTEGER,
  max_bytes    BIGINT,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by   UUID REFERENCES users(id)
);
CREATE TRIGGER tg_ret_touch BEFORE UPDATE ON retention_rules FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 19 · VULNERABILITIES
-- =====================================================================
CREATE TABLE vuln_scans (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ,
  source        TEXT NOT NULL,                    -- 'osv','nvd','local_apt','pip_audit','npm_audit'
  status        TEXT NOT NULL DEFAULT 'running',
  findings_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE vuln_findings (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id            TEXT NOT NULL,
  severity          vuln_severity NOT NULL,
  cvss_score        NUMERIC(3,1),
  cvss_vector       TEXT,
  component         TEXT NOT NULL,                 -- 'openssl','bind9','urllib3'
  installed_version TEXT NOT NULL,
  fixed_version     TEXT,
  source            TEXT NOT NULL,                 -- 'apt','pip','npm', etc.
  description       TEXT,
  references_       TEXT[] NOT NULL DEFAULT '{}',  -- external URLs (NVD/MITRE/GHSA/Vulners)
  discovered_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  status            vuln_status NOT NULL DEFAULT 'open',
  suppressed_until  TIMESTAMPTZ,
  suppression_note  TEXT,
  ticket_ref        TEXT,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (cve_id, component, installed_version)
);
CREATE INDEX ix_vuln_status_sev ON vuln_findings (status, severity);
CREATE TRIGGER tg_vuln_touch BEFORE UPDATE ON vuln_findings FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 20 · UPDATES / UPGRADES
-- =====================================================================
CREATE TABLE update_snapshots (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reason       TEXT NOT NULL,                     -- 'pre-upgrade','manual','scheduled'
  storage_path TEXT NOT NULL,
  size_bytes   BIGINT,
  db_included  BOOLEAN NOT NULL DEFAULT TRUE,
  config_included BOOLEAN NOT NULL DEFAULT TRUE,
  files_included  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   UUID REFERENCES users(id),
  retention_until TIMESTAMPTZ
);

CREATE TABLE update_history (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  component      TEXT NOT NULL,                   -- 'meridian-app','nginx','bind9', package name
  from_version   TEXT,
  to_version     TEXT NOT NULL,
  applied_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  applied_by     UUID REFERENCES users(id),
  snapshot_id    UUID REFERENCES update_snapshots(id),
  status         TEXT NOT NULL DEFAULT 'ok',       -- 'ok','rolled_back','failed'
  notes          TEXT
);

-- `apt upgrade + optional reboot` runs. Two creation paths:
--   scheduled_for IS NULL  → triggered immediately by an admin clicking
--                            "Update+Reboot now". A row is created and the
--                            Celery task `run_update` fires inline.
--   scheduled_for IS NOT NULL → queued for later. The beat task
--                               `meridian.jobs.upgrade.fire_scheduled`
--                               picks up any unstarted row whose
--                               scheduled_for <= now() and runs it.
CREATE TABLE system_update_runs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by   UUID REFERENCES users(id),
  scheduled_for  TIMESTAMPTZ,                     -- NULL = immediate
  reboot         BOOLEAN NOT NULL DEFAULT TRUE,
  status         TEXT NOT NULL DEFAULT 'pending', -- pending|running|ok|failed|cancelled
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  exit_code      INTEGER,
  output_tail    TEXT,                            -- last ~8 KB of stdout/err
  packages_count INTEGER,
  reboot_required BOOLEAN NOT NULL DEFAULT FALSE, -- /var/run/reboot-required existed
  cancelled_by   UUID REFERENCES users(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_sysupd_pending ON system_update_runs (scheduled_for)
  WHERE status = 'pending';
CREATE TRIGGER tg_sysupd_touch BEFORE UPDATE ON system_update_runs
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 21 · WEBHOOKS (inbound + outbound)
-- =====================================================================
CREATE TABLE webhooks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  direction     webhook_direction NOT NULL,
  name          TEXT NOT NULL,
  description   TEXT NOT NULL,
  url           TEXT,                             -- outbound target; inbound URL is derived
  events        TEXT[] NOT NULL DEFAULT '{}',
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  secret_id     UUID REFERENCES secrets(id),      -- HMAC signing key
  created_by    UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_webhook_touch BEFORE UPDATE ON webhooks FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE webhook_deliveries (
  id           BIGSERIAL PRIMARY KEY,
  webhook_id   UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  direction    webhook_direction NOT NULL,
  event        TEXT NOT NULL,
  payload      JSONB NOT NULL,
  status       TEXT NOT NULL,                     -- 'ok','failed','deferred'
  http_status  INTEGER,
  response     TEXT,
  ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempt      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX ix_wh_deliveries_time ON webhook_deliveries (webhook_id, ts DESC);

-- =====================================================================
-- 22 · CERTIFICATES (portal + monitored + mTLS client)
-- =====================================================================
CREATE TABLE acme_accounts (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider     TEXT NOT NULL DEFAULT 'letsencrypt',
  environment  TEXT NOT NULL DEFAULT 'production',-- production|staging
  email        TEXT NOT NULL,
  key_secret_id UUID REFERENCES secrets(id),       -- ACME account private key
  dns_provider TEXT,                               -- 'cloudflare','route53', etc.
  dns_secret_id UUID REFERENCES secrets(id),       -- DNS API credentials
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, environment, email)
);
CREATE TRIGGER tg_acme_acc_touch BEFORE UPDATE ON acme_accounts FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE certificates (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cert_type          cert_type NOT NULL,
  common_name        TEXT NOT NULL,
  sans               TEXT[] NOT NULL DEFAULT '{}',
  issuer             TEXT,
  serial_hex         TEXT,
  fingerprint_sha256 TEXT,
  valid_from         TIMESTAMPTZ,
  valid_until        TIMESTAMPTZ,
  key_type           cert_key_type,
  key_size           INTEGER,
  signature_alg      TEXT,
  leaf_pem           TEXT,
  chain_pem          TEXT,
  private_key_ref    UUID REFERENCES secrets(id), -- NULL for monitor-only
  auto_renew         BOOLEAN NOT NULL DEFAULT FALSE,
  managed            BOOLEAN NOT NULL DEFAULT FALSE, -- we control renewal vs just watching
  acme_account_id    UUID REFERENCES acme_accounts(id),
  challenge          cert_challenge_type,
  renew_before_days  INTEGER NOT NULL DEFAULT 30,
  deploy_target      TEXT,                          -- 'nginx','haproxy','traefik','none'
  last_renewed_at    TIMESTAMPTZ,
  last_renew_status  TEXT,
  ocsp_stapled       BOOLEAN NOT NULL DEFAULT FALSE,
  ct_logged          BOOLEAN NOT NULL DEFAULT FALSE,
  hsts_policy        TEXT,
  notify_channels    UUID[] NOT NULL DEFAULT '{}',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at         TIMESTAMPTZ,
  revoke_reason      TEXT
);
CREATE INDEX ix_certs_type_expiring ON certificates (cert_type, valid_until);
CREATE TRIGGER tg_certs_touch BEFORE UPDATE ON certificates FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

ALTER TABLE api_tokens ADD CONSTRAINT fk_token_client_cert FOREIGN KEY (bound_client_cert_id) REFERENCES certificates(id);

CREATE TABLE csr_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_cn     TEXT NOT NULL,
  sans           TEXT[] NOT NULL DEFAULT '{}',
  key_type       cert_key_type NOT NULL,
  key_secret_id  UUID REFERENCES secrets(id),     -- the generated private key
  csr_pem        TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT 'pending', -- 'pending','signed','cancelled'
  submitted_ca   TEXT,
  signed_cert_id UUID REFERENCES certificates(id),
  created_by     UUID REFERENCES users(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_csr_touch BEFORE UPDATE ON csr_requests FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE cert_events (
  id          BIGSERIAL PRIMARY KEY,
  cert_id     UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  event       TEXT NOT NULL,                      -- 'issued','renewed','revoked','deployed','rotated','uploaded'
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id    UUID REFERENCES users(id),
  detail      JSONB
);
CREATE INDEX ix_cert_events_cert ON cert_events (cert_id, ts DESC);

CREATE TABLE ca_store (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  purpose      TEXT,                              -- 'internal_tls','client_mtls','code_signing'
  pem          TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  trusted      BOOLEAN NOT NULL DEFAULT TRUE,
  imported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  imported_by  UUID REFERENCES users(id)
);

-- =====================================================================
-- 23 · FEATURE TOGGLES / SCOPE MANAGER
-- =====================================================================
CREATE TABLE features (
  key          TEXT PRIMARY KEY,                  -- 'dns.dig_sandbox','network.tcpdump',...
  category     TEXT NOT NULL,
  description  TEXT NOT NULL,                     -- matches UI rule
  scope        scope_visibility NOT NULL DEFAULT 'both',
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  requires_license_feature TEXT,                  -- NULL if always available
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER tg_features_touch BEFORE UPDATE ON features FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE group_feature_gates (
  group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  feature_key TEXT NOT NULL REFERENCES features(key) ON DELETE CASCADE,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (group_id, feature_key)
);

-- =====================================================================
-- 24 · TICKETING LINKS (external systems: Jira, ServiceNow, Zendesk)
-- =====================================================================
CREATE TABLE ticket_links (
  id            BIGSERIAL PRIMARY KEY,
  entity_type   TEXT NOT NULL,                    -- 'wizard_run','vuln_finding','monitor_incident','cert'
  entity_key    TEXT NOT NULL,
  system        TEXT NOT NULL,                    -- 'jira','servicenow','zendesk','github'
  ticket_id     TEXT NOT NULL,
  ticket_url    TEXT,
  linked_by     UUID REFERENCES users(id),
  linked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (entity_type, entity_key, system, ticket_id)
);
CREATE INDEX ix_tix_entity ON ticket_links (entity_type, entity_key);

-- =====================================================================
-- 25 · WORKSPACES (shared team spaces)
-- =====================================================================
CREATE TABLE workspaces (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  description TEXT,
  owner_id    UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_in_ws   TEXT NOT NULL DEFAULT 'member',   -- 'owner','editor','member','viewer'
  added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

-- =====================================================================
-- 26 · DASHBOARDS (per-user customizable + workspace-level)
-- =====================================================================
CREATE TABLE dashboards (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id     UUID REFERENCES users(id),
  workspace_id UUID REFERENCES workspaces(id),
  name         TEXT NOT NULL,
  is_default   BOOLEAN NOT NULL DEFAULT FALSE,
  layout       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ordered list of {widget, x, y, w, h, config}
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (owner_id IS NOT NULL OR workspace_id IS NOT NULL)
);
CREATE TRIGGER tg_dashboards_touch BEFORE UPDATE ON dashboards FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- =====================================================================
-- 27 · VIEWS (common queries)
-- =====================================================================

-- Expiring certs in the next 30 days
CREATE OR REPLACE VIEW v_certs_expiring AS
SELECT id, common_name, cert_type, issuer, valid_until,
       (valid_until - now())::INTERVAL AS remaining,
       EXTRACT(DAY FROM (valid_until - now()))::INTEGER AS days_remaining,
       auto_renew
FROM certificates
WHERE revoked_at IS NULL
  AND valid_until BETWEEN now() AND now() + INTERVAL '30 days'
ORDER BY valid_until ASC;

-- Current user permissions (rolled up: role ∪ group ∪ user, minus user-deny)
CREATE OR REPLACE VIEW v_user_effective_permissions AS
  SELECT u.id AS user_id, rp.permission
  FROM users u
  JOIN role_permissions rp ON rp.role = u.role
  WHERE u.enabled AND u.deleted_at IS NULL
UNION
  SELECT ug.user_id, gp.permission
  FROM user_groups ug
  JOIN group_permissions gp ON gp.group_id = ug.group_id
UNION
  SELECT up.user_id, up.permission
  FROM user_permissions up
  WHERE up.allow = TRUE AND (up.expires_at IS NULL OR up.expires_at > now())
EXCEPT
  SELECT up.user_id, up.permission
  FROM user_permissions up
  WHERE up.allow = FALSE;

-- Latest wizard run per user+target
CREATE OR REPLACE VIEW v_latest_wizard_runs AS
SELECT DISTINCT ON (user_id, wizard_key, target)
       id, wizard_key, user_id, target, started_at, completed_at, outcome
FROM wizard_runs
ORDER BY user_id, wizard_key, target, started_at DESC;

-- Pre-made job summary
CREATE OR REPLACE VIEW v_job_status AS
SELECT j.name, j.description, j.cron_expression, j.enabled,
       j.last_run_at, j.last_run_status, j.next_run_at,
       (SELECT count(*) FROM job_runs jr WHERE jr.job_id = j.id AND jr.started_at > now() - INTERVAL '7 days') AS runs_7d
FROM jobs j ORDER BY j.name;

-- =====================================================================
-- 28 · SEED DATA
-- =====================================================================

-- System groups
INSERT INTO groups (id, name, description, is_system) VALUES
  (gen_random_uuid(), 'super-admins', 'Full control of the platform', TRUE),
  (gen_random_uuid(), 'admins',        'Platform administration, user + feature management', TRUE),
  (gen_random_uuid(), 'analysts',      'Full tool access, own dashboard, API tokens', TRUE),
  (gen_random_uuid(), 'viewers',       'Read-only access to results', TRUE),
  (gen_random_uuid(), 'ddi-ssh',       'Allowed SSH login to the host (zsh default shell)', TRUE),
  (gen_random_uuid(), 'cert-managers', 'Can request, rotate, and revoke certificates', TRUE),
  (gen_random_uuid(), 'ad-operators',  'Permitted to perform AD write actions (reset, unlock, etc.)', TRUE);

-- Permissions (illustrative subset — full catalog populated by app migration)
INSERT INTO permissions (key, description, category, requires_two_person) VALUES
  ('dns.sandbox',               'Run dig and propagation checks in the sandbox',                   'dns',    FALSE),
  ('dns.bulk_lookup',            'Run bulk DNS lookups across multiple domains',                    'dns',    FALSE),
  ('network.ping',               'Run ping / traceroute / port scan / HTTP test / SNMP walk (respects scope_of_use + deny CIDRs)','network',FALSE),
  ('network.snmp_walk',          'Run SNMP v1/v2c/v3 walks against internal devices',              'network',FALSE),
  ('network.tcpdump',            'Trigger packet capture via tcpdump (capped duration)',            'network',TRUE),
  ('network.iperf_server',       'Activate iperf3 server mode (opens port 5201)',                   'network',TRUE),
  ('ad.user.read',               'Look up AD users, groups, computers',                             'ad',     FALSE),
  ('ad.user.unlock',             'Unlock AD user accounts',                                         'ad',     FALSE),
  ('ad.user.reset_password',     'Reset AD user passwords',                                         'ad',     TRUE),
  ('ad.user.disable',            'Disable AD user accounts',                                        'ad',     TRUE),
  ('infoblox.read',              'Read from Infoblox Grid / CSP',                                   'infoblox',FALSE),
  ('infoblox.write',             'Modify records in Infoblox Grid / CSP',                          'infoblox',TRUE),
  ('cert.request',               'Request new certificates via ACME or CSR',                        'cert',   FALSE),
  ('cert.revoke',                'Revoke certificates',                                             'cert',   TRUE),
  ('cert.private_key_download',  'Download a private key from the vault',                           'cert',   TRUE),
  ('admin.users.manage',         'Create, edit, delete users',                                      'admin',  FALSE),
  ('admin.services.restart',     'Restart system services (nginx, bind, etc.)',                    'admin',  TRUE),
  ('admin.branding.edit',        'Edit branding and AUP text',                                     'admin',  FALSE),
  ('admin.feature_gates.edit',   'Enable/disable features globally or per group',                  'admin',  FALSE),
  ('admin.impersonate',          'Log in as another user (audit-logged)',                          'admin',  TRUE),
  ('admin.scope.manage',         'Edit scope allow/deny CIDR rules (internal/external overrides)', 'admin',  FALSE),
  ('admin.integrations.manage',  'Configure Directory backend integrations (endpoints + credentials)','admin',TRUE),
  ('admin.vuln.read',            'View vulnerability findings + scan history',                    'admin',  FALSE),
  ('admin.vuln.manage',          'Trigger scans, suppress or accept-risk CVE findings',            'admin',  FALSE),
  ('admin.system.health.read',   'Read live system health checks (services/disk/mem/cert/DB/keys)','admin',  FALSE),
  ('admin.system.repair',        'Run bounded repair actions (reload BIND, reseed permissions, restart services, re-run integrity scan)','admin',TRUE),
  ('admin.updates.read',         'View pending OS/Python updates, version drift, snapshot + update history','admin',FALSE),
  ('admin.updates.snapshot',     'Take a pre-upgrade snapshot (DB + config) via scripts/backup.sh',      'admin',FALSE),
  ('admin.updates.apply',        'Run apt upgrade + reboot — immediately or on a schedule',              'admin',TRUE),
  ('runbook.create',             'Create and edit personal runbooks (chain tools into named workflows)', 'runbook',FALSE),
  ('runbook.run',                'Execute a runbook (each step is gated by its own tool permission)',    'runbook',FALSE),
  ('runbook.share',              'Share a runbook with another user or group',                           'runbook',FALSE),
  ('admin.webhooks.manage',      'Create, edit, delete inbound + outbound webhooks (HMAC signed)',       'admin',  FALSE),
  ('admin.devices.view',         'Read network device inventory, config snapshots, and diffs',           'admin',  FALSE),
  ('admin.devices.manage',       'Add / edit / remove network devices, rotate credentials, trigger backups','admin',TRUE);

-- Super admin gets everything
INSERT INTO role_permissions (role, permission)
SELECT 'super_admin', key FROM permissions;

-- Admin gets most except two-person privileged items (granted via group membership case by case)
INSERT INTO role_permissions (role, permission)
SELECT 'admin', key FROM permissions WHERE category <> 'ad' OR key = 'ad.user.read';

-- Analyst: read tools + non-destructive actions
INSERT INTO role_permissions (role, permission) VALUES
  ('analyst','dns.sandbox'),
  ('analyst','dns.bulk_lookup'),
  ('analyst','network.ping'),
  ('analyst','ad.user.read'),
  ('analyst','infoblox.read'),
  ('analyst','cert.request');

-- Viewer: read-only
INSERT INTO role_permissions (role, permission) VALUES
  ('viewer','dns.sandbox'),
  ('viewer','ad.user.read'),
  ('viewer','infoblox.read');

-- Branding default row
INSERT INTO branding (id) VALUES (1);


-- Retention defaults
INSERT INTO retention_rules (scope, description, keep_days, keep_count, max_bytes) VALUES
  ('audit_events',     'Audit log events — forensic trail',                      90,   NULL,     NULL),
  ('query_history',    'Per-user query history (tool runs)',                     30,   500,      NULL),
  ('file_repo_user',   'Per-user file quota soft-cap 500 MB / hard-cap 1 GB',   NULL, NULL,     1073741824),
  ('backups_daily',    'Full daily backups to rotate',                           7,    7,        NULL),
  ('backups_weekly',   'Weekly full backups to keep',                            NULL, 4,        NULL),
  ('backups_monthly',  'Monthly full backups to keep',                           NULL, 3,        NULL),
  ('bind9_query_log',  'BIND9 recursive query log window',                       NULL, NULL,     NULL),
  ('celery_results',   'Celery task result payloads',                            7,    NULL,     NULL),
  ('pcap_files',       'Packet capture files created via tcpdump sandbox',       14,   NULL,     NULL),
  ('monitor_raw',      'Raw monitor samples (5-second granularity)',             30,   NULL,     NULL),
  ('monitor_rollups_5m','Monitor 5-minute rollups',                              90,   NULL,     NULL),
  ('monitor_rollups_1h','Monitor hourly rollups',                                365,  NULL,     NULL);

-- Pre-made jobs (matches the Scheduled Jobs mockup one-to-one)
INSERT INTO jobs (name, description, cron_expression, handler, enabled) VALUES
  ('audit-log-cleanup',      'Delete audit events older than retention window',                            '0 3 * * *',  'meridian.jobs.retention:audit_cleanup',  TRUE),
  ('query-history-cleanup',  'Keep last 500 results per user, max 30 days',                                '0 4 * * *',  'meridian.jobs.retention:query_cleanup',  TRUE),
  ('file-repo-quota',        'Enforce per-user quota (soft 500 MB / hard 1 GB)',                            '0 5 * * 0',  'meridian.jobs.retention:file_quota',     TRUE),
  ('backup-rotation',        'Keep 7 daily, 4 weekly, 3 monthly backup snapshots',                          '0 2 * * *',  'meridian.jobs.backup:rotate',            TRUE),
  ('bind9-query-log-roll',   'Roll BIND9 query log to 48-hour window',                                      '0 * * * *',  'meridian.jobs.bind9:roll_querylog',      TRUE),
  ('pg-vacuum-analyze',      'Daily VACUUM ANALYZE; reclaims dead tuples and refreshes planner stats',     '0 1 * * *',  'meridian.jobs.db:vacuum_analyze',        TRUE),
  ('pg-reindex',             'Weekly REINDEX of hot tables (audit_events, query_history, monitor_*)',      '0 1 * * 0',  'meridian.jobs.db:reindex_hot',           TRUE),
  ('celery-result-purge',    'Delete Celery task results older than 7 days',                                '0 3 * * *',  'meridian.jobs.retention:celery_purge',   TRUE),
  ('stale-session-cleanup',  'Revoke user sessions idle > 12 hours',                                        '0 */6 * * *','meridian.jobs.sessions:cleanup',         TRUE),
  ('monitor-retention',      'Rotate monitor raw/5m/1h per retention policy',                               '0 2 * * *',  'meridian.jobs.monitor:retention',        TRUE),
  ('pcap-cleanup',           'Delete pcap files older than 14 days (pinned captures skipped)',              '0 4 * * *',  'meridian.jobs.retention:pcap_cleanup',   TRUE),
  ('db-full-backup',         'Compressed pg_dump of all databases to /backups/full/',                       '0 2 * * *',  'meridian.jobs.backup:full_db',           TRUE),
  ('db-wal-ship',            'Ship PostgreSQL WAL every 15 minutes for point-in-time recovery',             '*/15 * * * *','meridian.jobs.backup:wal_ship',         TRUE),
  ('vuln-scan',              'OSV + NVD scan of installed OS + app dependencies',                           '0 2 * * *',  'meridian.jobs.vuln:scan',                TRUE),
  ('cert-expiry-check',      'Scan every monitored cert; alert at 30/14/7 days remaining',                  '0 6 * * *',  'meridian.jobs.cert:expiry_check',        TRUE),
  ('cert-auto-renew',        'Renew any auto-managed cert within its renew threshold',                      '0 2 * * *',  'meridian.jobs.cert:auto_renew',          TRUE),
  ('stale-ad-report',        'Weekly list of AD accounts inactive > 90 days',                               '0 7 * * 1',  'meridian.jobs.ad:stale_accounts',        TRUE),
  ('pre-update-snapshot',    'Event-triggered; fires before any auto-update to enable rollback',            NULL,          'meridian.jobs.upgrade:pre_snapshot',     TRUE),
  ('feature-health-ping',    'Hourly ping of each enabled integration; marks unreachable',                  '30 * * * *', 'meridian.jobs.health:feature_ping',      TRUE),
  ('device-config-backup',   'Pull running-config from every enabled network device; stores on SHA change only', '0 3 * * *', 'meridian.jobs.devices:backup_all',      TRUE),
  ('device-retention',       'Trim device config snapshots per retention_rules.scope = device_snapshots',   '0 5 * * *',  'meridian.jobs.devices:retention',       TRUE),
  ('monitor-sample-due',     'Evaluate every enabled monitor whose interval has elapsed and write a sample', '* * * * *', 'meridian.jobs.monitor:sample_due', TRUE);

UPDATE jobs SET kind = 'on_event' WHERE name = 'pre-update-snapshot';

-- Wizard registry (matches the Wizards page one-to-one)
INSERT INTO wizards (key, category, name, description) VALUES
  ('dns.resolve_fail',       'ddi',     'Why isn''t my domain resolving?',           'Registrar → delegation → SOA match → authoritative → cache → DNSSEC → propagation'),
  ('mail.delivery',          'ddi',     'Why isn''t my mail being delivered?',       'MX → A/AAAA → PTR → SPF → DKIM → DMARC → TLS-RPT → BIMI → MTA-STS → blacklist → open-relay'),
  ('ssl.deep_inspect',       'ddi',     'SSL/TLS deep inspect',                       'Chain → intermediates → SNI → hostname → expiry → OCSP → CT log → TLS versions → ciphers → HSTS → redirects'),
  ('dnssec.chain',           'ddi',     'DNSSEC chain walker',                        'Visual root → TLD → zone trust chain; flags the exact broken link'),
  ('zone.health',            'ddi',     'Zone health check',                          'Dangling CNAMEs, missing glue, SOA drift, NSEC integrity, expired records'),
  ('registrar.mismatch',     'ddi',     'Registrar vs authoritative mismatch',       'Hijack and stale-update detector — compares registrar NS list vs live'),
  ('domain.bringup',         'ddi',     'New domain bring-up checklist',              'Green/yellow/red scorecard across 10+ required records'),
  ('cloudflare.validator',   'ddi',     'Cloudflare / CDN config validator',          'CNAME, redirects, origin cert, CF ranges, DNSSEC compat, Always-HTTPS'),
  ('typosquat.sweep',        'ddi',     'Typosquat sweep + threat hunt',              'IDN / homograph / typo variants; which are registered, live, or hosting mail'),
  ('dmarc.tuning',           'ddi',     'DMARC tuning guide',                         'Walks p=none → quarantine → reject with aggregate report analysis'),
  ('axfr.audit',             'ddi',     'Zone transfer (AXFR) audit',                 'Tests every authoritative NS for exposed zone transfers'),
  ('ip.reputation',          'ddi',     'IP reputation deep dive',                    'ASN, route, WHOIS, AbuseIPDB, Shodan InternetDB, blacklists, history'),
  ('infoblox.drift',         'ddi',     'Infoblox drift detector',                    'Live DNS vs Infoblox expected state diff'),
  ('network.reachability',   'network', 'Why can''t I reach X?',                      'Ping → trace → port → DNS → TLS → HTTP. Stops and explains first failure.'),
  ('network.up_for_everyone','network', 'Is this site down for me or everyone?',     'Local box result vs external probe result side-by-side'),
  ('mail.flow_validator',    'network', 'Mail-flow validator',                        'Full mail stack end-to-end: MX, auth, TLS-RPT, blacklist, relay');

-- Features (matches Admin Panel feature toggles one-to-one)
INSERT INTO features (key, category, description, scope) VALUES
  ('dns.dig_sandbox',          'dns',         'Sandboxed dig queries for all users · custom flags, record types, resolvers · no shell access',                    'both'),
  ('dns.propagation',          'dns',         'Queries 16+ global public resolvers in parallel · detects drift and regional cache issues',                        'both'),
  ('network.tcpdump',          'network',     'Packet capture via tcpdump · admin-gated · duration & size capped · pcap download to File Repo',                   'internal'),
  ('network.snmp_walk',        'network',     'SNMP v1/v2c/v3 walks against internal devices · credentials stored in encrypted vault',                           'internal'),
  ('network.iperf_server',     'network',     'Allow this host to act as an iperf3 server for inbound throughput tests · opens port 5201',                      'internal'),
  ('wizard.typosquat',         'wizard',      'Brand-protection threat hunt · generates IDN/homograph/typo variants · checks registration, MX, SSL',             'external'),
  ('integration.shodan',       'integration', 'Free no-key IP intel (internetdb.shodan.io) · open ports, hostnames, tags, known CVEs',                           'external'),
  ('integration.infoblox_grid','integration', 'On-prem Infoblox DNS query API · read-only via WAPI · bind credentials in vault',             'internal'),
  ('integration.infoblox_csp', 'integration', 'Cloud SaaS DDI · read + permission-gated write via CSP API · deep-links to csp.infoblox.com',                     'both'),
  ('integration.ad',           'integration', 'User, group, DL, and computer lookup · read-only by default · gated write (unlock, reset, enable/disable)',       'internal'),
  ('integration.entra',        'integration', 'Cloud identity parallel to AD · Graph API · Conditional Access, guest audit, sign-in logs, Exchange Online',      'both');

-- AUP v1 seed (admin replaces via Branding tab)
INSERT INTO aup_versions (body, active) VALUES (
  E'ACCEPTABLE USE POLICY\n\nThis system is restricted to authorized personnel only. All access attempts and queries are logged. Unauthorized use is prohibited.',
  TRUE
);

-- =====================================================================
-- 28b · NETWORK DEVICES (routers, firewalls, switches — config backup + drift)
-- =====================================================================
CREATE TYPE device_kind AS ENUM (
  'cisco_ios','cisco_iosxr','cisco_nxos','cisco_asa',
  'juniper_junos','arista_eos',
  'palo_alto','fortinet','mikrotik','generic_ssh'
);

CREATE TABLE network_devices (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name               TEXT NOT NULL UNIQUE,
  description        TEXT,
  kind               device_kind NOT NULL,
  mgmt_host          TEXT NOT NULL,              -- IP or DNS name
  mgmt_port          INTEGER NOT NULL DEFAULT 22,
  username           TEXT,
  secret_id          UUID REFERENCES secrets(id),-- SSH password or private-key body
  enable_secret_id   UUID REFERENCES secrets(id),-- Cisco enable password (optional)
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  auto_backup        BOOLEAN NOT NULL DEFAULT TRUE,
  retain_snapshots_count INTEGER NOT NULL DEFAULT 50,  -- nightly trim keeps N most recent
  tags               TEXT[] NOT NULL DEFAULT '{}',
  site               TEXT,
  last_backup_at     TIMESTAMPTZ,
  last_backup_ok     BOOLEAN,
  last_backup_error  TEXT,
  last_config_sha256 TEXT,
  config             JSONB NOT NULL DEFAULT '{}', -- per-device knobs (command timeouts, enable flag)
  created_by         UUID REFERENCES users(id),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_devices_enabled ON network_devices (enabled, auto_backup);
CREATE TRIGGER tg_devices_touch BEFORE UPDATE ON network_devices FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE device_config_snapshots (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id          UUID NOT NULL REFERENCES network_devices(id) ON DELETE CASCADE,
  ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  trigger_kind       TEXT NOT NULL,               -- 'scheduled','manual','on_change','initial'
  raw_config         TEXT NOT NULL,
  size_bytes         INTEGER NOT NULL,
  sha256_hex         TEXT NOT NULL,
  line_count         INTEGER,
  prev_snapshot_id   UUID REFERENCES device_config_snapshots(id),
  diff_from_prev     TEXT,                        -- unified diff vs prev, computed on insert
  diff_lines_added   INTEGER,
  diff_lines_removed INTEGER,
  captured_by        UUID REFERENCES users(id)
);
CREATE INDEX ix_snap_device_ts ON device_config_snapshots (device_id, ts DESC);

CREATE TABLE device_backup_runs (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at       TIMESTAMPTZ,
  trigger_kind       TEXT NOT NULL,
  devices_attempted  INTEGER NOT NULL DEFAULT 0,
  devices_ok         INTEGER NOT NULL DEFAULT 0,
  devices_changed    INTEGER NOT NULL DEFAULT 0,
  devices_failed     INTEGER NOT NULL DEFAULT 0,
  status             TEXT NOT NULL DEFAULT 'running'
);
CREATE INDEX ix_device_runs_started ON device_backup_runs (started_at DESC);

-- =====================================================================
-- 29 · OSS COMPONENTS (third-party attribution / SBOM)
-- =====================================================================
CREATE TABLE oss_components (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT NOT NULL,
  version        TEXT NOT NULL,
  category       TEXT NOT NULL,                   -- 'os_package','python','node','font','service','system'
  license_spdx   TEXT NOT NULL,                   -- 'MIT','BSD-3-Clause','Apache-2.0','GPL-2.0','MPL-2.0','OFL-1.1', ...
  license_family TEXT NOT NULL CHECK (license_family IN
                    ('permissive','weak_copyleft','strong_copyleft','network_copyleft','font','public_domain','proprietary','other')),
  license_text   TEXT,                            -- full text inline for offline browsing + download bundle
  homepage_url   TEXT,
  source_url     TEXT,                            -- required for copyleft: where end users can obtain source
  purpose        TEXT,                            -- human-readable reason this component is in Meridian
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  removed_at     TIMESTAMPTZ,                     -- soft delete when a package is no longer installed
  UNIQUE (name, version, category)
);
CREATE INDEX ix_oss_family   ON oss_components (license_family) WHERE removed_at IS NULL;
CREATE INDEX ix_oss_name_trgm ON oss_components USING gin (name gin_trgm_ops);

-- SBOM snapshot archive (regeneratable from oss_components but frozen for audit)
CREATE TABLE sbom_snapshots (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  format         TEXT NOT NULL,                   -- 'cyclonedx_json','cyclonedx_xml','spdx_json','spdx_tv'
  content        TEXT NOT NULL,
  component_count INTEGER NOT NULL,
  generated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  generated_by   TEXT NOT NULL DEFAULT 'system'   -- 'install','manual','scheduled'
);
CREATE INDEX ix_sbom_generated ON sbom_snapshots (generated_at DESC);

-- Scan runs: diff vs previous, compliance signal for admin
CREATE TABLE oss_scan_runs (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at          TIMESTAMPTZ,
  added_count           INTEGER NOT NULL DEFAULT 0,
  removed_count         INTEGER NOT NULL DEFAULT 0,
  license_change_count  INTEGER NOT NULL DEFAULT 0,
  status                TEXT NOT NULL DEFAULT 'running',
  detail                JSONB
);

-- Append the OSS scan job to the pre-made catalog
INSERT INTO jobs (name, description, cron_expression, handler, enabled) VALUES
  ('oss-component-scan',
   'Discover installed OS packages (dpkg -l), Python deps (pip list), and Node deps (npm ls); refresh oss_components and regenerate SBOM snapshots; alert admin on new strong-copyleft / AGPL / license changes',
   '0 4 * * *',
   'meridian.jobs.oss:scan',
   TRUE);

-- =====================================================================
-- 30 · VERSION PINNING (installer consults this manifest)
-- =====================================================================
-- Meridian pins every third-party dependency to a specific tested version.
-- Too new or too old both break. The installer reads this table on every
-- install/upgrade, compares to what's on the box, and bails on mismatches.
CREATE TABLE version_manifest (
  component_name   TEXT NOT NULL,
  category         TEXT NOT NULL,                  -- 'os_package','python','node','font','service','kernel','glibc','systemd','postgresql_major'
  pinned_version   TEXT NOT NULL,                  -- the canonical tested version
  min_version      TEXT,                           -- installer accepts down to this
  max_version      TEXT,                           -- installer accepts up to this
  tested_on_debian TEXT NOT NULL DEFAULT '13',     -- '12', '13', or '12,13'; primary target is 13
  purpose          TEXT,                           -- human-readable why-it's-needed
  release_channel  TEXT NOT NULL DEFAULT 'stable', -- 'stable','lts','edge'
  manifest_version INTEGER NOT NULL DEFAULT 1,     -- bumps when Meridian team ships a new tested combination
  upstream_url     TEXT,
  changelog_url    TEXT,                           -- so admin can see what they're missing if pinned lags
  notes            TEXT,
  pinned_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (component_name, category, tested_on_debian)
);
CREATE INDEX ix_vm_category ON version_manifest (category, tested_on_debian);

-- Drift detection: what the `meridian-nip doctor` command found vs. the manifest
CREATE TABLE version_drift (
  id              BIGSERIAL PRIMARY KEY,
  component_name  TEXT NOT NULL,
  category        TEXT NOT NULL,
  found_version   TEXT NOT NULL,
  expected_version TEXT NOT NULL,
  severity        TEXT NOT NULL,                   -- 'ok','warn','block'
  detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at     TIMESTAMPTZ,
  note            TEXT
);
CREATE INDEX ix_drift_unresolved ON version_drift (severity, detected_at DESC) WHERE resolved_at IS NULL;

-- Seed the pinned manifest for 1.0.0.
-- Components where Debian 12 and 13 ship different base versions have one
-- row per target. Components that are identical (or that we pin via pip/npm
-- so the OS version is irrelevant) have a single row tagged '12,13'.

-- --- Debian 13 (primary) -------------------------------------------------
-- Version ranges are deliberately permissive for OS-managed packages:
-- Debian 13 receives security point-releases that bump patch numbers. We pin
-- the minor/major but accept any upstream patch within that range without
-- raising a drift alarm. Python packages remain exactly pinned — we control
-- those via requirements.txt.
INSERT INTO version_manifest (component_name, category, pinned_version, min_version, max_version, tested_on_debian, purpose) VALUES
  ('nginx',          'os_package', '1.26.3',  '1.26.0', '1.28.99', '13',  'Web server, TLS termination, reverse proxy'),
  ('bind9',          'os_package', '9.20.21', '9.20.0', '9.22.99', '13',  'Recursive DNS resolver for sandboxed dig queries'),
  ('postgresql',     'os_package', '17.2',    '17.0',   '17.99',   '13',  'Primary database'),
  ('valkey',         'os_package', '8.1.1',   '7.2.0',  '8.99.0',  '13',  'Celery broker + cache (BSD-3 fork of Redis)'),
  ('openssl',        'os_package', '3.5.5',   '3.2.0',  '3.99.0',  '13',  'TLS library used across the stack'),
  ('python3',        'os_package', '3.13.5',  '3.13.0', '3.13.99', '13',  'Language runtime for the app'),
  ('kernel',         'system',     '6.12',    '6.6',    '6.99',    '13',  'Debian 13 stable kernel series (WSL2 uses 6.6+)'),
  ('glibc',          'system',     '2.40',    '2.40',   '2.42',    '13',  'C library'),
  ('systemd',        'system',     '256',     '256',    '258',     '13',  'Service manager');

-- --- Debian 12 (fallback) ------------------------------------------------
INSERT INTO version_manifest (component_name, category, pinned_version, min_version, max_version, tested_on_debian, purpose) VALUES
  ('nginx',          'os_package', '1.24.0',  '1.22.0', '1.24.99', '12',  'Web server, TLS termination, reverse proxy'),
  ('bind9',          'os_package', '9.18.28', '9.18.0', '9.18.99', '12',  'Recursive DNS resolver for sandboxed dig queries'),
  ('postgresql',     'os_package', '15.6',    '15.0',   '15.99',   '12',  'Primary database'),
  ('redis-server',   'os_package', '7.0.15',  '7.0.0',  '7.0.99',  '12',  'Celery broker + cache · BSD-licensed 7.0.x (pre-RSAL)'),
  ('openssl',        'os_package', '3.0.14',  '3.0.0',  '3.0.99',  '12',  'TLS library used across the stack'),
  ('python3',        'os_package', '3.11.9',  '3.11.0', '3.11.99', '12',  'Language runtime for the app'),
  ('kernel',         'system',     '6.1',     '6.1',    '6.1.99',  '12',  'Debian 12 stable kernel series'),
  ('glibc',          'system',     '2.36',    '2.36',   '2.36.99', '12',  'C library'),
  ('systemd',        'system',     '252',     '252',    '254',     '12',  'Service manager');

-- --- Shared between 12 and 13 --------------------------------------------
-- OS packages pinned to Debian 13's current versions with a permissive max —
-- point-release patches should not trigger drift alarms. Python packages are
-- pinned to what requirements.txt ships.
INSERT INTO version_manifest (component_name, category, pinned_version, min_version, max_version, tested_on_debian, purpose) VALUES
  ('certbot',        'os_package', '4.0.0',   '2.0.0',  '4.99.0',  '12,13', 'ACME client for Let''s Encrypt'),
  ('fail2ban',       'os_package', '1.1.0',   '1.0.0',  '1.99.0',  '12,13', 'Intrusion prevention'),
  ('apparmor',       'os_package', '4.1.0',   '3.0.0',  '4.99.0',  '12,13', 'Mandatory access control profiles'),
  ('fastapi',        'python',     '0.115.6', '0.115.0','0.115.99','12,13', 'Web framework (pinned via requirements.txt)'),
  ('uvicorn',        'python',     '0.32.1',  '0.30.0', '0.32.99', '12,13', 'ASGI server'),
  ('gunicorn',       'python',     '23.0.0',  '23.0.0', '23.99.0', '12,13', 'Production WSGI worker pool'),
  ('celery',         'python',     '5.3.6',   '5.3.0',  '5.3.99',  '12,13', 'Background task queue'),
  ('sqlalchemy',     'python',     '2.0.36',  '2.0.30', '2.0.99',  '12,13', 'ORM and query builder'),
  ('jinja2',         'python',     '3.1.3',   '3.1.0',  '3.1.99',  '12,13', 'Template engine'),
  ('psycopg2',       'python',     '2.9.9',   '2.9.0',  '2.9.99',  '12,13', 'PostgreSQL driver (works against PG 15 and 17)'),
  ('dnspython',      'python',     '2.6.1',   '2.4.0',  '2.6.99',  '12,13', 'DNS library for DDI tools and wizards'),
  ('cryptography',   'python',     '42.0.5',  '41.0.0', '42.0.99', '12,13', 'X.509 parsing, key generation, license verification'),
  ('tailwindcss',    'node',       '3.4.1',   '3.3.0',  '3.4.99',  '12,13', 'Utility-first CSS'),
  ('alpinejs',       'node',       '3.13.5',  '3.12.0', '3.13.99', '12,13', 'Client-side interactivity');

-- =====================================================================
-- 31 · LICENSE EXPIRY WARNINGS + DEMO LIMITS
-- =====================================================================

-- Demo usage counters (per-user per-day) — tracked inline instead of config_kv for queryability
CREATE TABLE demo_usage (
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  usage_date   DATE NOT NULL DEFAULT CURRENT_DATE,
  query_count  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, usage_date)
);

-- =====================================================================
-- 32 · DATABASE ENCRYPTION & TAMPER EVIDENCE
-- =====================================================================
-- Layers used across Meridian:
-- · Layer 1 (filesystem): LUKS volume, set up by installer. Not represented in schema.
-- · Layer 2 (app-level field encryption): already in place via secrets vault + mfa_secret_enc.
-- · Layer 3 (row-hash tamper evidence): below. HMAC-chained row hashes on sensitive tables.
-- · Layer 4 (direct-SQL restriction): pg_hba.conf configuration, not schema.

-- Every tamper-evident table gets a row_hash column computed at insert by a trigger.
-- The trigger pulls the most-recent row_hash of the same table and includes it in the HMAC
-- input, forming a hash chain. Any modification breaks every subsequent row.

ALTER TABLE audit_events           ADD COLUMN row_hash BYTEA;
ALTER TABLE cert_events            ADD COLUMN row_hash BYTEA;
ALTER TABLE approvals              ADD COLUMN row_hash BYTEA;
ALTER TABLE impersonations         ADD COLUMN row_hash BYTEA;
ALTER TABLE update_history         ADD COLUMN row_hash BYTEA;

-- HMAC key is stored in /etc/meridian/master.key (0600 meridian:meridian), read by the
-- app at startup and passed into this function via a SECURITY DEFINER wrapper in the app.
-- The DB-level fn_row_hmac() below is a placeholder that the app replaces with a key-bound
-- variant using pgcrypto's hmac() once the master key is loaded.
CREATE OR REPLACE FUNCTION fn_row_hmac(canonical TEXT, prev_hash BYTEA)
RETURNS BYTEA AS $$
DECLARE
  key_material BYTEA;
BEGIN
  -- Retrieves key from a PG-local secure config set by the app at boot.
  -- If the key is not set, returns NULL — triggers will then skip, logged as a degraded state.
  SELECT decode(current_setting('meridian.row_hmac_key', TRUE), 'hex') INTO key_material;
  IF key_material IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN hmac(canonical || encode(COALESCE(prev_hash, '\x00'::bytea), 'hex'), key_material, 'sha256');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Generic chain-hash trigger: pass the table name + canonical row text via trigger args.
-- The trigger implementations live in db/triggers/row_hash.sql (one per table) to keep
-- the canonical-field list explicit and reviewable per table. This file sets up the
-- column only; migrations install the per-table triggers.

-- Integrity scan results
-- =====================================================================
-- Account-recovery (5 security questions; 3 random must match to unlock).
-- Answers are normalized (trim + lowercase + collapse whitespace) and
-- hashed with Argon2id — same params as password hashing, distinct domain.
-- Recovery via questions does NOT reset the password directly; it mints a
-- one-time reset token so the user can set a new one. Layered: questions +
-- token + rate-limit beats questions alone.
-- =====================================================================
CREATE TABLE user_recovery_questions (
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  position      SMALLINT NOT NULL CHECK (position BETWEEN 1 AND 5),
  question_text TEXT NOT NULL,
  answer_hash   TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, position)
);

CREATE TABLE password_reset_tokens (
  token_hash   TEXT PRIMARY KEY,              -- sha256 of the token; the
                                              -- token itself lives only in the
                                              -- email / challenge-success pane
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ,
  ip           TEXT,
  user_agent   TEXT
);
CREATE INDEX ix_reset_tokens_user ON password_reset_tokens (user_id, created_at DESC);

-- Rate-limit table for the recovery challenge. Hits are cleared on success.
CREATE TABLE user_recovery_attempts (
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip            TEXT,
  outcome       TEXT NOT NULL,    -- 'fail' | 'locked' | 'ok'
  PRIMARY KEY (user_id, attempted_at)
);

CREATE TABLE db_integrity_scans (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at   TIMESTAMPTZ,
  status         TEXT NOT NULL DEFAULT 'running',   -- running | ok | mismatch | error
  tables_scanned TEXT[] NOT NULL DEFAULT '{}',
  rows_checked   BIGINT NOT NULL DEFAULT 0,
  mismatches     INTEGER NOT NULL DEFAULT 0,
  mismatch_detail JSONB,
  alert_fired    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_integrity_scan_time ON db_integrity_scans (started_at DESC);

-- Pre-made job: daily hash-chain verification
INSERT INTO jobs (name, description, cron_expression, handler, enabled) VALUES
  ('db-integrity-scan',
   'Verifies the HMAC hash-chain on tamper-evident tables (audit_events, license, cert_events, approvals, etc.) · any mismatch raises a CRITICAL alert · detects offline DB tampering',
   '0 5 * * *',
   'meridian.jobs.integrity:scan',
   TRUE);

-- =====================================================================
-- DNS resolvers · admin-curated house list + per-user overrides
-- ---------------------------------------------------------------------
-- owner_user_id = NULL  →  house resolver, visible to everyone, managed
-- by admins. The 16 canonical public resolvers (originally a frozen
-- Python tuple in app/dns/propagation.py) are seeded below as house
-- entries with is_propagation_default = TRUE so the Propagation tool
-- uses them out of the box. Admins can add / edit / delete.
--
-- owner_user_id = <uuid>  →  personal resolver, only that user sees it
-- in Dig / Reverse dropdowns. Never used by the Propagation tool
-- (canonical reproducibility is preserved by keeping that list under
-- admin control).
--
-- Region is a free-text tag so the dropdown can group entries
-- geographically (US / EU / APAC / Global) — several canonicals have
-- >1000 ms RTT from the US and only make sense for regional users.
-- =====================================================================
CREATE TABLE resolvers (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id            UUID REFERENCES users(id) ON DELETE CASCADE,
  name                     TEXT NOT NULL,
  ip                       INET NOT NULL,
  region                   TEXT,
  notes                    TEXT,
  is_propagation_default   BOOLEAN NOT NULL DEFAULT FALSE,
  -- Free-text group label (e.g. "Corp DNS", "Corp Cache", "Staging").
  -- Used by the Dig / Propagation / Hop Trace "Limit to group" selectors
  -- so a multi-environment customer can target one tier at a time. NULL
  -- means ungrouped / always available.
  group_tag                TEXT,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_resolvers_owner ON resolvers (owner_user_id);
CREATE INDEX ix_resolvers_group ON resolvers (group_tag);
-- Uniqueness is per-scope, per-IP, per-group. Same IP can appear in
-- multiple groups (a customer's "Corp DNS" group might happen to use
-- 1.1.1.1 separately from the House-default Cloudflare entry), but
-- within one scope + one group, duplicate IPs are blocked to catch
-- accidental re-adds.
CREATE UNIQUE INDEX ux_resolvers_owner_ip_group ON resolvers
  (COALESCE(owner_user_id, '00000000-0000-0000-0000-000000000000'::uuid),
   ip,
   COALESCE(group_tag, ''));
CREATE TRIGGER tg_resolvers_touch BEFORE UPDATE ON resolvers
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

-- Seed: the 16 canonical public resolvers as house entries. Admins can
-- rename / re-tag / delete / un-default any of these after install;
-- they are just first-boot defaults, not a locked list.
INSERT INTO resolvers (name, ip, region, is_propagation_default, notes) VALUES
  ('Cloudflare',    '1.1.1.1',        'Global', TRUE,  'Cloudflare public 1.1.1.1 · anycast'),
  ('Google',        '8.8.8.8',        'Global', TRUE,  'Google Public DNS · anycast'),
  ('Quad9',         '9.9.9.9',        'Global', TRUE,  'Quad9 · malware-filtered'),
  ('OpenDNS',       '208.67.222.222', 'US',     TRUE,  'Cisco OpenDNS / Umbrella'),
  ('AdGuard',       '94.140.14.14',   'Global', TRUE,  'AdGuard DNS · ads blocked'),
  ('NextDNS',       '45.90.28.193',   'Global', TRUE,  'NextDNS anycast'),
  ('Verisign',      '64.6.64.6',      'US',     TRUE,  'Verisign public resolver'),
  ('DNS.Watch',     '84.200.69.80',   'EU',     TRUE,  'DNS.Watch · Germany'),
  ('Mullvad',       '194.242.2.2',    'EU',     TRUE,  'Mullvad · Sweden'),
  ('Yandex',        '77.88.8.8',      'RU',     TRUE,  'Yandex · Russia'),
  ('Neustar',       '156.154.70.1',   'US',     TRUE,  'Neustar UltraDNS public'),
  ('Comodo',        '8.26.56.26',     'US',     TRUE,  'Comodo Secure DNS'),
  ('SafeDNS',       '195.46.39.39',   'RU',     TRUE,  'SafeDNS · Russia'),
  ('CleanBrowsing', '185.228.168.168','Global', TRUE,  'CleanBrowsing filtered'),
  ('Hurricane EL',  '74.82.42.42',    'US',     TRUE,  'Hurricane Electric'),
  ('CenturyLink',   '205.171.3.65',   'US',     TRUE,  'CenturyLink / Lumen');

-- =====================================================================
-- END · schema.sql
-- =====================================================================
