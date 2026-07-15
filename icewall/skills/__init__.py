"""Agent skills: markdown knowledge modules loaded into an agent's system
prompt when it spawns. See `icewall/skills/library/` for the bundled set."""
from icewall.skills.loader import Skill, SkillRegistry, render_skills

__all__ = ["Skill", "SkillRegistry", "render_skills"]
