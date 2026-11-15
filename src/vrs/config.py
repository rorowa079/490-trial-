"""Configuration loading: default.yaml <- hardware.yaml <- local/override file."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"


def _merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(override: str | os.PathLike | dict | None = None) -> dict[str, Any]:
    """Return the merged settings.

    ``override`` may be a path to a YAML file or a dict (handy in tests). When
    omitted, the VRS_CONFIG environment variable and config/local.yaml are used.
    """
    cfg: dict[str, Any] = {}
    for name in ("default.yaml", "hardware.yaml", "local.yaml"):
        path = CONFIG_DIR / name
        if path.exists():
            _merge(cfg, yaml.safe_load(path.read_text()) or {})

    if override is None and os.environ.get("VRS_CONFIG"):
        override = os.environ["VRS_CONFIG"]
    if isinstance(override, dict):
        _merge(cfg, override)
    elif override:
        _merge(cfg, yaml.safe_load(Path(override).read_text()) or {})

    data_dir = Path(cfg["data_dir"])
    if not data_dir.is_absolute():
        data_dir = (REPO_ROOT / data_dir).resolve()
    cfg["data_dir"] = str(data_dir)
    # Relative paths in the settings are relative to the repository, not the working directory.
    for section, key in _PATH_SETTINGS:
        node = cfg
        for part in section:
            node = node.get(part, {})
        value = node.get(key)
        if value and not Path(value).is_absolute():
            node[key] = str((REPO_ROOT / value).resolve())
    return cfg


_PATH_SETTINGS = (
    (("keys",), "software_dir"), (("updates",), "public_key_file"), (("updates",), "manifest"),
    (("privacy", "redaction"), "face_model"), (("supply_chain",), "bom_file"), (("hotlist_sync",), "ca_file"),
    (("api", "tls"), "cert_file"), (("api", "tls"), "key_file"), (("api", "tls"), "client_ca_file"),
    (("vision",), "yolo_weights"), (("vision",), "plate_weights"),
)


def data_path(cfg: dict, *parts: str) -> Path:
    path = Path(cfg["data_dir"]).joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
