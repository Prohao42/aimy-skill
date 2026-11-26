"""Validate the bundled Agent Skill library.

Every skill must be a directory with a SKILL.md carrying YAML frontmatter
(name + description).  This keeps the 100+ skills loadable by agents.
"""

import re
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parents[1] / "ai-mian" / "hack-skills" / "skills"
FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


def test_skill_directories_and_frontmatter():
    skill_dirs = sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir())
    assert len(skill_dirs) == 104
    for directory in skill_dirs:
        skill_file = directory / "SKILL.md"
        assert skill_file.exists(), "%s is missing SKILL.md" % directory.name
        text = skill_file.read_text(encoding="utf-8")
        match = FRONTMATTER.match(text)
        assert match, "%s has no YAML frontmatter" % directory.name
        block = match.group(1)
        assert re.search(r"^name:\s*\S+", block, re.M), "%s missing name" % directory.name
        assert re.search(r"^description:\s*\S+", block, re.M), (
            "%s missing description" % directory.name
        )
