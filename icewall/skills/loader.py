"""Skill discovery and loading.

A *skill* is a markdown file with YAML frontmatter that injects domain expertise
into an agent's system prompt at spawn time — so users can extend or specialize
an agent's behavior without editing Python.

Frontmatter fields:
  name        : short unique slug (defaults to the filename stem)
  description : one-line summary (shown by `icewall skills`)
  roles       : list of agent roles this applies to, or ["all"]
  priority    : higher loads first (default 0)
  enabled     : set false to keep a skill on disk but inert (default true)

Targeting: a skill attaches to an agent role if the role is in its `roles`
frontmatter (or `roles: [all]`). A skill's role can also be inferred from its
parent directory name under a skills dir (e.g. `.../analyzer/sqli.md`).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml

from icewall.config import AgentRole, SkillsConfig

_ROLE_VALUES = {r.value for r in AgentRole}


@dataclass
class Skill:
    name: str
    description: str
    roles: list[str]  # role values, possibly ["all"]
    priority: int
    body: str
    path: str
    enabled: bool = True

    def applies_to(self, role: str) -> bool:
        return self.enabled and ("all" in self.roles or role in self.roles)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split a markdown file into (frontmatter dict, body)."""
    if text.lstrip().startswith("---"):
        stripped = text.lstrip()
        end = stripped.find("\n---", 3)
        if end != -1:
            fm_block = stripped[3:end].strip()
            body = stripped[end + 4 :].lstrip("\n")
            try:
                data = yaml.safe_load(fm_block) or {}
                if isinstance(data, dict):
                    return data, body
            except yaml.YAMLError:
                pass
    return {}, text


def load_skill_file(path: str, inferred_role: Optional[str] = None) -> Optional[Skill]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    fm, body = _parse_frontmatter(text)
    if not body.strip():
        return None

    name = str(fm.get("name") or Path(path).stem)
    roles_raw = fm.get("roles")
    if isinstance(roles_raw, str):
        roles = [roles_raw]
    elif isinstance(roles_raw, list):
        roles = [str(r) for r in roles_raw]
    elif inferred_role:
        roles = [inferred_role]
    else:
        roles = ["all"]
    # Validate role names (keep "all"; drop unknowns to avoid silent misrouting).
    roles = [r for r in roles if r == "all" or r in _ROLE_VALUES] or ["all"]

    return Skill(
        name=name,
        description=str(fm.get("description", "")).strip(),
        roles=roles,
        priority=int(fm.get("priority", 0) or 0),
        body=body.strip(),
        path=str(path),
        enabled=bool(fm.get("enabled", True)),
    )


class SkillRegistry:
    def __init__(self, skills: list[Skill]) -> None:
        # Later-loaded skills with the same name override earlier ones
        # (user dirs override bundled).
        self._by_name: dict[str, Skill] = {}
        for s in skills:
            self._by_name[s.name] = s

    @property
    def skills(self) -> list[Skill]:
        return list(self._by_name.values())

    @staticmethod
    def bundled_dir() -> str:
        return str(Path(__file__).parent / "library")

    @classmethod
    def discover(cls, cfg: Optional[SkillsConfig] = None) -> "SkillRegistry":
        cfg = cfg or SkillsConfig()
        dirs: list[str] = []
        if cfg.include_bundled:
            dirs.append(cls.bundled_dir())
        dirs.extend(cfg.dirs)

        disabled = set(cfg.disabled)
        skills: list[Skill] = []
        for d in dirs:
            skills.extend(cls._load_dir(d))
        # Apply config-level disable list.
        for s in skills:
            if s.name in disabled:
                s.enabled = False
        return cls(skills)

    @staticmethod
    def _load_dir(directory: str) -> list[Skill]:
        out: list[Skill] = []
        if not os.path.isdir(directory):
            return out
        for root, _dirs, files in os.walk(directory):
            inferred = os.path.basename(root)
            inferred_role = inferred if inferred in _ROLE_VALUES else None
            for fn in files:
                if not fn.lower().endswith((".md", ".markdown")):
                    continue
                skill = load_skill_file(os.path.join(root, fn), inferred_role)
                if skill:
                    out.append(skill)
        return out

    def for_role(self, role: str, names: Optional[list[str]] = None) -> list[Skill]:
        """Skills attached to `role`. If `names` is given (explicit selection
        from agent config), restrict to those and honor their order; otherwise
        return all matching, highest priority first."""
        matching = [s for s in self._by_name.values() if s.applies_to(role)]
        if names:
            chosen = []
            for n in names:
                s = self._by_name.get(n)
                if s and s.enabled:
                    chosen.append(s)
            return chosen
        return sorted(matching, key=lambda s: (-s.priority, s.name))


def render_skills(skills: Iterable[Skill]) -> str:
    """Render skills into a system-prompt section."""
    skills = list(skills)
    if not skills:
        return ""
    parts = [
        "\n\n# Loaded skills",
        "The following expertise modules have been loaded for you. Apply them.",
    ]
    for s in skills:
        parts.append(f"\n## Skill: {s.name}")
        if s.description:
            parts.append(f"_{s.description}_")
        parts.append(s.body)
    return "\n".join(parts)
