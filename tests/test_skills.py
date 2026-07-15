"""Tests for the per-agent skill system."""
from __future__ import annotations

import textwrap

import pytest

from icewall.config import AgentRole, IcewallConfig, SkillsConfig
from icewall.engine import Engine
from icewall.skills import SkillRegistry, render_skills
from icewall.skills.loader import _parse_frontmatter, load_skill_file


def test_bundled_skills_discovered():
    reg = SkillRegistry.discover(SkillsConfig())
    names = {s.name for s in reg.skills}
    assert "sql-injection-analysis" in names
    assert "false-positive-guards" in names


def test_skills_attach_to_correct_roles():
    reg = SkillRegistry.discover(SkillsConfig())
    analyzer = {s.name for s in reg.for_role("analyzer")}
    assert "sql-injection-analysis" in analyzer
    assert "command-injection-analysis" in analyzer
    # A validator-only skill must not leak into the analyzer.
    assert "false-positive-guards" not in analyzer
    assert "false-positive-guards" in {s.name for s in reg.for_role("validator")}


def test_agents_load_skills_at_spawn():
    eng = Engine(IcewallConfig.default())
    analyzer = eng.agents[AgentRole.ANALYZER]
    assert analyzer.skills, "analyzer should have skills loaded"
    system = analyzer._system()
    # Role tag stays first (providers route on it) and skill body is present.
    assert system.startswith("[ICEWALL-AGENT:analyzer]")
    assert "# Loaded skills" in system
    assert "parameterized" in system  # from the SQLi skill body


def test_explicit_skill_selection_overrides_auto():
    reg = SkillRegistry.discover(SkillsConfig())
    chosen = reg.for_role("analyzer", ["sql-injection-analysis"])
    assert [s.name for s in chosen] == ["sql-injection-analysis"]


def test_disabled_skill_is_not_attached():
    cfg = SkillsConfig(disabled=["false-positive-guards"])
    reg = SkillRegistry.discover(cfg)
    names = {s.name for s in reg.for_role("validator")}
    assert "false-positive-guards" not in names


def test_priority_ordering():
    reg = SkillRegistry.discover(SkillsConfig())
    triage = reg.for_role("triage")
    prios = [s.priority for s in triage]
    assert prios == sorted(prios, reverse=True)


def test_user_skill_dir_and_role_inference(tmp_path):
    # A skill file placed in a role-named subdir attaches to that role even with
    # no `roles` frontmatter.
    d = tmp_path / "analyzer"
    d.mkdir()
    (d / "custom.md").write_text(
        textwrap.dedent(
            """\
            ---
            description: custom analyzer rule
            ---
            Always flag use of the banned `dangerous_api()` helper.
            """
        ),
        encoding="utf-8",
    )
    reg = SkillRegistry.discover(SkillsConfig(dirs=[str(tmp_path)]))
    analyzer = {s.name for s in reg.for_role("analyzer")}
    assert "custom" in analyzer


def test_user_skill_overrides_bundled_by_name(tmp_path):
    (tmp_path / "over.md").write_text(
        textwrap.dedent(
            """\
            ---
            name: sql-injection-analysis
            roles: [analyzer]
            ---
            OVERRIDDEN BODY MARKER
            """
        ),
        encoding="utf-8",
    )
    reg = SkillRegistry.discover(SkillsConfig(dirs=[str(tmp_path)]))
    sql = next(s for s in reg.skills if s.name == "sql-injection-analysis")
    assert "OVERRIDDEN BODY MARKER" in sql.body


def test_frontmatter_parsing():
    fm, body = _parse_frontmatter("---\nname: x\nroles: [analyzer]\n---\nHello body")
    assert fm["name"] == "x"
    assert body == "Hello body"


def test_no_frontmatter_is_ok(tmp_path):
    p = tmp_path / "plain.md"
    p.write_text("Just guidance, no frontmatter.", encoding="utf-8")
    skill = load_skill_file(str(p), inferred_role="tracer")
    assert skill is not None
    assert skill.roles == ["tracer"]
    assert skill.applies_to("tracer")


def test_render_skills_empty():
    assert render_skills([]) == ""
