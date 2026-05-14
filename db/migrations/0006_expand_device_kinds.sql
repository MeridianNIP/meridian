-- 0006_expand_device_kinds.sql
-- Expands device_kind enum to cover the long tail of network gear an
-- SMB/enterprise admin actually owns. Original 10 enterprise types are
-- preserved; 22 more are added below. PostgreSQL enums are append-only
-- (no value rename / removal), which is fine — every netmiko-mapped
-- value here corresponds to a stable upstream device_type.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

-- Cisco family (XE was missing — common on cat switches)
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'cisco_iosxe';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'cisco_wlc';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'cisco_s300';

-- Aruba / HP
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'aruba_aoscx';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'aruba_os';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'hp_procurve';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'hp_comware';

-- Dell
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'dell_os10';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'dell_force10';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'dell_powerconnect';

-- Other big-co
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'huawei';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'extreme_exos';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'brocade_fastiron';

-- ADC / load balancers
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'f5_tmsh';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'citrix_netscaler';

-- Firewalls
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'sonicwall';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'pfsense';      -- linux backend
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'opnsense';     -- linux backend
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'sophos';       -- linux backend

-- SoHo / open-source
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'ubiquiti_edge';
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'ubiquiti_unifi'; -- linux backend
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'vyos';

-- NAS / appliance
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'synology';     -- linux backend
ALTER TYPE device_kind ADD VALUE IF NOT EXISTS 'qnap';         -- linux backend

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (6, '0006_expand_device_kinds.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
