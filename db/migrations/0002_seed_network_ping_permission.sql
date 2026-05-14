-- 0002_seed_network_ping_permission.sql
-- Fixes a boot-time bug: routes guarded by require_permission("network.ping")
-- (ping, traceroute, port-scan, HTTP test) referred to a permission key that
-- was never seeded. Every call would 403, regardless of role.
--
-- Adds the missing key + adjacent SNMP-walk key, grants super_admin + admin
-- + analyst as expected.

BEGIN;

INSERT INTO permissions (key, description, category, requires_two_person) VALUES
  ('network.ping',      'Run ping / traceroute / port scan / HTTP test / SNMP walk (respects scope_of_use + deny CIDRs)', 'network', FALSE),
  ('network.snmp_walk', 'Run SNMP v1/v2c/v3 walks against internal devices', 'network', FALSE)
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
SELECT 'super_admin', 'network.ping'     ON CONFLICT DO NOTHING;
INSERT INTO role_permissions (role, permission)
SELECT 'super_admin', 'network.snmp_walk' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions (role, permission)
SELECT 'admin',       'network.ping'     ON CONFLICT DO NOTHING;
INSERT INTO role_permissions (role, permission)
SELECT 'admin',       'network.snmp_walk' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions (role, permission)
SELECT 'analyst',     'network.ping'     ON CONFLICT DO NOTHING;

COMMIT;
