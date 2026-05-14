# Import registers all wizard implementations via their @wizard decorator.
from app.wizards import (  # noqa: F401
    dns_wizards,
    integration_wizards,
    mail_wizards,
    network_wizards,
    resolve_fail,
    ssl_wizards,
)
from app.wizards.engine import list_wizards, run_wizard  # noqa: F401
