"""Network device automation — SSH-based config backup + drift.

Public surface:
    DeviceKind               — enum of supported kinds, mirrors schema's device_kind
    fetch_running_config     — high-level SSH pull that returns the raw config text
    backup_device            — fetch + persist + diff (writes one DeviceConfigSnapshot
                               only when sha256 differs from the previous one)
    backup_all               — iterate every enabled+auto_backup device and invoke
                               backup_device for each; the celery job is a thin
                               wrapper around this
"""
from app.devices.backup import backup_all, backup_device  # noqa: F401
from app.devices.connection import DEVICE_COMMANDS, fetch_running_config  # noqa: F401
