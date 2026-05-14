"""Scheduled Reports subsystem.

* `generators.py` — pure functions that produce a list of rows for each
  report_type. No I/O beyond the DB session they're handed.
* `renderers.py` — rows → CSV / HTML artifact.
* `runner.py` — schedule-aware executor: claims a schedule row, runs
  the generator, writes the artifact, emails if configured, records
  the run. Also provides the ad-hoc `run_now` entry point.
* `cron.py` — cadence → cron expression + next-fire computation.
* `routes.py` — FastAPI surface (list/create/edit/delete schedules,
  list runs, download artifact, ad-hoc run).
"""
