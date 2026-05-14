from __future__ import annotations

from fastapi import APIRouter

from app.admin.appeals_routes import router as admin_appeals_router
from app.admin.routes import router as admin_router
from app.admin.credentials_routes import router as admin_credentials_router
from app.admin.fail2ban_routes import router as admin_fail2ban_router
from app.admin.health_routes import router as admin_health_router
from app.admin.queues_routes import router as admin_queues_router
from app.admin.network_routes import router as admin_network_router
from app.admin.integrations_routes import router as admin_integrations_router
from app.admin.log_shipping_routes import router as admin_log_shipping_router
from app.admin.retention_routes import router as admin_retention_router
from app.admin.policy_routes import router as admin_policy_router
from app.admin.snmp_routes import router as admin_snmp_router
from app.admin.scope_routes import router as admin_scope_router
from app.admin.updates_routes import router as admin_updates_router
from app.admin.vuln_routes import router as admin_vuln_router
from app.devices.routes import router as admin_devices_router
from app.admin.users_api import router as admin_users_router
from app.approvals.routes import router as approvals_router
from app.auth.lockout_appeal import router as auth_lockout_appeal_router
from app.auth.routes import router as auth_router
from app.branding.routes import router as branding_router
from app.certs.routes import router as certs_router
from app.directory.routes import router as directory_router
from app.dns.resolver_routes import router as dns_resolvers_router
from app.dns.routes import router as dns_router
from app.files.routes import router as files_router
from app.links.routes import router as links_router
from app.messages.routes import router as messages_router
from app.monitors.routes import router as monitors_router
from app.network.routes import router as network_router
from app.notifications.routes import router as notifications_router
from app.reports.routes import router as reports_router
from app.runbooks.routes import router as runbooks_router
from app.webhooks.routes import admin_router as admin_webhooks_router
from app.webhooks.routes import public_router as webhooks_public_router
from app.settings_routes import router as settings_router
from app.tokens_routes import router as tokens_router
from app.users.gdpr import router as users_gdpr_router
from app.wizards.routes import router as wizards_router


api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(auth_router)
api_v1.include_router(auth_lockout_appeal_router)
api_v1.include_router(dns_router)
api_v1.include_router(dns_resolvers_router)
api_v1.include_router(network_router)
api_v1.include_router(monitors_router)
api_v1.include_router(certs_router)
api_v1.include_router(files_router)
api_v1.include_router(links_router)
api_v1.include_router(directory_router)
api_v1.include_router(messages_router)
api_v1.include_router(wizards_router)
api_v1.include_router(approvals_router)
api_v1.include_router(notifications_router)
api_v1.include_router(reports_router)
api_v1.include_router(runbooks_router)
api_v1.include_router(webhooks_public_router)
api_v1.include_router(admin_webhooks_router)
api_v1.include_router(admin_router)
api_v1.include_router(admin_scope_router)
api_v1.include_router(admin_integrations_router)
api_v1.include_router(admin_log_shipping_router)
api_v1.include_router(admin_retention_router)
api_v1.include_router(admin_snmp_router)
api_v1.include_router(admin_policy_router)
api_v1.include_router(admin_vuln_router)
api_v1.include_router(admin_credentials_router)
api_v1.include_router(admin_appeals_router)
api_v1.include_router(admin_fail2ban_router)
api_v1.include_router(admin_health_router)
api_v1.include_router(admin_queues_router)
api_v1.include_router(admin_network_router)
api_v1.include_router(admin_updates_router)
api_v1.include_router(admin_devices_router)
api_v1.include_router(admin_users_router)
api_v1.include_router(branding_router)
api_v1.include_router(settings_router)
api_v1.include_router(tokens_router)
api_v1.include_router(users_gdpr_router)


@api_v1.get("/", include_in_schema=False)
def api_root() -> dict:
    return {
        "api": "v1",
        "routes": [r.path for r in api_v1.routes if hasattr(r, "path")],
    }
