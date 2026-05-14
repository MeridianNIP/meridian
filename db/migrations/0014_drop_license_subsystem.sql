-- 0014_drop_license_subsystem.sql
--
-- Removes the entire commercial-license subsystem. Meridian is now
-- Apache 2.0 (LICENSE + NOTICE at repo root, 2026-05-13). Every install
-- gets full feature parity — no demo tier, no paid tier, no key entry,
-- no expiry warnings. The user owns whatever they deploy.
--
-- Tables removed:
--   - license
--   - license_activations
--   - license_verifications
--   - license_revocations
--   - license_warning_dismissals
--
-- Enum removed:
--   - license_tier
--
-- Rows pruned:
--   - permissions row 'admin.license.manage'
--   - jobs rows 'license-verify' and 'license-expiry-notify' (handlers
--     are gone)
--
-- Schema kept (intentional, not license-related):
--   - feature_gates.requires_license_feature column — repurposed as
--     "requires_optional_feature" / left in place; no migration churn.
--   - oss_components.license_spdx / license_family — these describe
--     THIRD-PARTY package licenses, not our own. They stay.
--
-- This is a one-way migration. There is no "0014 down".

BEGIN;

-- Prune jobs that referenced the deleted handlers (safe even if jobs
-- already disabled or absent).
DELETE FROM jobs WHERE handler IN (
  'meridian.jobs.license:verify',
  'meridian.jobs.license:expiry_notify'
);

-- Prune permission rows.
DELETE FROM role_permissions WHERE permission = 'admin.license.manage';
DELETE FROM permissions      WHERE key         = 'admin.license.manage';

-- Drop the tables. CASCADE handles any leftover FK references we
-- haven't explicitly tracked. Use IF EXISTS so re-runs are no-ops.
DROP TABLE IF EXISTS license_warning_dismissals CASCADE;
DROP TABLE IF EXISTS license_revocations        CASCADE;
DROP TABLE IF EXISTS license_verifications      CASCADE;
DROP TABLE IF EXISTS license_activations        CASCADE;
DROP TABLE IF EXISTS license                    CASCADE;

-- Drop the enum after tables that used it.
DROP TYPE IF EXISTS license_tier CASCADE;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (14, '0014_drop_license_subsystem.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
