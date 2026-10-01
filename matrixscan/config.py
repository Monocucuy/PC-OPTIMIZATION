"""Configuración persistente en %APPDATA%\\MatrixScan (o ~/.config/matrixscan)."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .util import IS_WINDOWS

_lock = threading.Lock()


def config_dir() -> Path:
    if IS_WINDOWS and os.environ.get("APPDATA"):
        base = Path(os.environ["APPDATA"]) / "MatrixScan"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "matrixscan"
    base.mkdir(parents=True, exist_ok=True)
    return base


def defaults() -> dict:
    return {
        "scan_roots": [str(Path.home())],
        "exclude_paths": [],
        "large_min_mb": 100,
        "unused_days": 180,
        "dup_min_mb": 1,
        "dup_skip_appdata": True,
        "vt_api_key": "",
    }


_LIMITS = {
    "large_min_mb": (1, 100_000),
    "unused_days": (1, 3650),
    "dup_min_mb": (0, 100_000),
}


def _path() -> Path:
    return config_dir() / "config.json"


def load() -> dict:
    cfg = defaults()
    try:
        with open(_path(), encoding="utf-8") as fh:
            stored = json.load(fh)
        if isinstance(stored, dict):
            cfg.update({k: v for k, v in stored.items() if k in cfg})
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


def save(updates: dict) -> dict:
    with _lock:
        cfg = load()
        for key, value in updates.items():
            if key not in cfg:
                continue
            if key in _LIMITS:
                lo, hi = _LIMITS[key]
                try:
                    value = max(lo, min(hi, float(value)))
                except (TypeError, ValueError):
                    continue
                if float(value).is_integer():
                    value = int(value)
            elif key in ("scan_roots", "exclude_paths"):
                if not isinstance(value, list):
                    continue
                value = [str(v).strip() for v in value if str(v).strip()]
                if key == "scan_roots" and not value:
                    value = defaults()["scan_roots"]
            elif key == "dup_skip_appdata":
                value = bool(value)
            elif key == "vt_api_key":
                value = str(value).strip()
            cfg[key] = value
        tmp = _path().with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, _path())
        return cfg


def public_view(cfg: dict) -> dict:
    """Configuración para el frontend, sin exponer la API key completa."""
    view = {k: v for k, v in cfg.items() if k != "vt_api_key"}
    key = cfg.get("vt_api_key") or ""
    view["has_vt_key"] = bool(key)
    view["vt_key_hint"] = ("••••" + key[-4:]) if len(key) >= 8 else ""
    return view
