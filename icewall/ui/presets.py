"""Saved configuration presets for the UI.

A preset is a full Icewall config with a name + description, stored as a YAML
file under `<root>/` (default `.icewall/presets`). Every save is validated by
`IcewallConfig` so a preset can always be loaded back into a scan.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from icewall.config import IcewallConfig

_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _safe_name(name: str) -> str:
    slug = _NAME_RE.sub("-", name.strip()).strip("-")
    if not slug:
        raise ValueError("preset name must contain letters or digits")
    return slug


class PresetStore:
    def __init__(self, root: str | Path = ".icewall/presets") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        return self.root / f"{_safe_name(name)}.yaml"

    def list(self) -> list[dict]:
        out = []
        for p in sorted(self.root.glob("*.yaml")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            out.append(
                {
                    "name": data.get("name", p.stem),
                    "description": data.get("description", ""),
                }
            )
        return out

    def get(self, name: str) -> Optional[dict]:
        p = self._path(name)
        if not p.exists():
            return None
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return data

    def save(self, name: str, config: dict, description: str = "") -> dict:
        # Validate before persisting: a stored preset must always load.
        IcewallConfig.model_validate(config)
        safe = _safe_name(name)
        payload = {"name": safe, "description": description, "config": config}
        self._path(safe).write_text(
            yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        return {"name": safe, "description": description}

    def delete(self, name: str) -> bool:
        p = self._path(name)
        if p.exists():
            p.unlink()
            return True
        return False

    def import_file(self, path: str | Path, name: Optional[str] = None) -> dict:
        """Import an Icewall config file (e.g. icewall.yaml) as a preset.

        Accepts either a bare config (top-level `providers`/`agents`) or a preset
        envelope ({name, description, config}). The config is validated before it
        is stored. Note: inline `api_key:` values are copied verbatim into the
        preset file (kept under the git-ignored workshop root, like icewall.yaml).
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"no such file: {path}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("config file is not a mapping")
        if "config" in data and "providers" not in data:
            config = data["config"]  # a preset envelope
        else:
            config = data  # a bare config
        preset_name = name or data.get("name") or p.stem
        return self.save(preset_name, config, description=f"Imported from {p.name}")

    def config_for(self, name: str) -> IcewallConfig:
        data = self.get(name)
        if data is None:
            raise KeyError(f"no preset named '{name}'")
        return IcewallConfig.model_validate(data.get("config", {}))
