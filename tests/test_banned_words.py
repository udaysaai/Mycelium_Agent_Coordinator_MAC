"""
test_banned_words.py - Enforcement of Rule R6 Prohibited Claims

Asserts that zero banned words or marketing claims appear across any
code, comment, UI string, documentation, or report file.
"""

from pathlib import Path
import re
import pytest

BANNED_PATTERNS = [
    r"100%",
    r"bulletproof",
    r"robust",
    r"fully hardened",
    r"guaranteed",
    r"cryptographically secure",
    r"unbreakable",
    r"enterprise-grade",
    r"compliant",
    r"compliance",
    r"flawless"
]

IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".pytest_cache",
    "__pycache__",
    "runtime",
    "dist-installer",
    "win-unpacked"
}

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_no_banned_words_in_source_or_docs():
    """Scan all .py, .md, .html, .js, and .css files for prohibited claims."""
    pattern = re.compile("|".join(BANNED_PATTERNS), re.IGNORECASE)
    violations = []

    for path in ROOT_DIR.rglob("*"):
        if any(ignored in path.parts for ignored in IGNORE_DIRS):
            continue
        if not path.is_file():
            continue
        if path.name in ("test_banned_words.py", "ci.yml"):
            continue

        if path.suffix in (".py", ".md", ".html", ".js"):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                matches = pattern.findall(line)
                if matches:
                    rel_path = path.relative_to(ROOT_DIR)
                    violations.append(f"{rel_path}:{idx} {matches} -> {line.strip()[:100]}")

        elif path.suffix == ".css":
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # In CSS, percentage dimensions like width: 100% are layout units, not claims.
            # Flag any non-percentage banned word, and flag 100% in CSS comments.
            css_banned = [w for w in BANNED_PATTERNS if w != r"100%"]
            css_pattern = re.compile(r"\b(" + "|".join(css_banned) + r")\b", re.IGNORECASE)

            for idx, line in enumerate(content.splitlines(), 1):
                if "/*" in line and "100%" in line:
                    rel_path = path.relative_to(ROOT_DIR)
                    violations.append(f"{rel_path}:{idx} ['100% in comment'] -> {line.strip()[:100]}")

                m = css_pattern.findall(line)
                if m:
                    rel_path = path.relative_to(ROOT_DIR)
                    violations.append(f"{rel_path}:{idx} {m} -> {line.strip()[:100]}")

    assert violations == [], f"Found {len(violations)} prohibited word violation(s):\n" + "\n".join(violations)
