# Importing these modules registers Celery tasks on import.
# The celery_app include list (in app/celery_app.py) covers these by dotted
# module path; this __init__ makes `from app.jobs import ...` work for
# programs that want to invoke them directly (scheduler, CLI, tests).
from app.jobs import integrity, retention  # noqa: F401
