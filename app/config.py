from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_CONFIG_PATH = "/etc/meridian/meridian.conf"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MERIDIAN_",
        env_file=None,
        case_sensitive=False,
        extra="ignore",
    )

    # --- Portal identity ---
    portal_name: str = "Meridian"
    portal_domain: str = "localhost"
    scope_of_use: str = Field("both", pattern="^(internal|external|both)$")
    timezone: str = "UTC"

    # --- Data stores ---
    db_dsn: str = "postgresql://meridian:meridian@127.0.0.1:5432/meridian"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- Crypto key material (read from disk, never from env) ---
    master_key_path: Path = Path("/etc/meridian/secrets/master.key")
    row_hmac_key_path: Path = Path("/etc/meridian/secrets/row_hmac.key")

    # --- External services ---
    bind9_resolver: str = "127.0.0.1"
    license_server: str = "https://meridiannip.com"
    manifest_version: str = "dev"
    airgapped: bool = False

    # --- Security defaults (overridden live from the branding table) ---
    idle_timeout_default_min: int = 30
    idle_timeout_max_min: int = 1440

    # --- Paths ---
    install_root: Path = Path("/opt/meridian")
    data_root: Path = Path("/var/lib/meridian")
    log_root: Path = Path("/var/log/meridian")


def _parse_conf_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        out[k.strip()] = v
    return out


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    conf_path = Path(os.environ.get("MERIDIAN_CONFIG", DEFAULT_CONFIG_PATH))
    overrides = _parse_conf_file(conf_path)
    return Settings(**overrides)


def load_key(path: Path) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"Key file not found: {path}. Has install.sh been run?")
    data = path.read_bytes()
    if len(data) != 32:
        raise RuntimeError(f"Key at {path} is {len(data)} bytes, expected 32")
    return data
