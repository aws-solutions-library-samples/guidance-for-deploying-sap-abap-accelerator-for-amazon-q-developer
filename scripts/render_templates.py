#!/usr/bin/env python3
"""Replace repo-specific values in project files using [tool.project-config] from pyproject.toml.

Files always contain real values, never placeholders. The script uses regex patterns
scoped to known URL structures to avoid false positives (e.g., ghcr.io/astral-sh/uv).

Usage:
    python3 scripts/render_templates.py              # Apply config to files
    python3 scripts/render_templates.py --dry-run     # Preview without writing
    python3 scripts/render_templates.py --set github_owner=myorg  # One-off override
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TEMPLATE_FILES = ["README.md", "Dockerfile.simple"]

# Each pattern: (regex, replacement_template)
# The regex matches the full string to replace; the template uses {config_key} for substitution.
# Patterns are intentionally specific to avoid matching unrelated URLs like ghcr.io/astral-sh/uv.
PATTERNS = [
    # ghcr.io/<owner>/<image_name> — only match our image name, not arbitrary images
    (
        r"ghcr\.io/[A-Za-z0-9._-]+/{image_name}",
        "ghcr.io/{github_owner}/{image_name}",
    ),
    # github.com/<owner>/<repo> — only match our repo name, not arbitrary repos
    (
        r"github\.com/[A-Za-z0-9._-]+/{github_repo}",
        "github.com/{github_owner}/{github_repo}",
    ),
]


def load_config() -> dict[str, str]:
    """Parse [tool.project-config] from pyproject.toml without third-party deps."""
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        print(
            "ERROR: pyproject.toml not found — run from project root", file=sys.stderr
        )
        sys.exit(1)

    config: dict[str, str] = {}
    in_section = False
    for line in pyproject.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[tool.project-config]":
            in_section = True
            continue
        if in_section:
            if stripped.startswith("["):
                break
            if "=" in stripped:
                key, _, value = stripped.partition("=")
                config[key.strip()] = value.strip().strip('"').strip("'")
    if not config:
        print(
            "ERROR: [tool.project-config] section not found in pyproject.toml",
            file=sys.stderr,
        )
        sys.exit(1)
    return config


def render(config: dict[str, str], dry_run: bool = False) -> int:
    """Replace old config values with new ones in template files. Returns count of files changed."""
    # Build compiled regex patterns with the current config's image_name/repo baked in
    compiled: list[tuple[re.Pattern[str], str]] = []
    for regex_tmpl, repl_tmpl in PATTERNS:
        regex = regex_tmpl.format(**config)
        repl = repl_tmpl.format(**config)
        compiled.append((re.compile(regex), repl))

    changed = 0
    for filename in TEMPLATE_FILES:
        path = Path(filename)
        if not path.exists():
            print(f"  SKIP {filename} (not found)")
            continue

        original = path.read_text()
        rendered = original
        for pattern, replacement in compiled:
            rendered = pattern.sub(replacement, rendered)

        if rendered != original:
            if dry_run:
                print(f"  WOULD UPDATE {filename}")
            else:
                path.write_text(rendered)
                print(f"  UPDATED {filename}")
            changed += 1
        else:
            print(f"  OK {filename} (no changes)")

    return changed


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without writing files"
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override a config value",
    )
    args = parser.parse_args()

    config = load_config()
    for override in args.set:
        if "=" not in override:
            print(
                f"ERROR: --set value must be KEY=VALUE, got: {override}",
                file=sys.stderr,
            )
            sys.exit(1)
        key, _, value = override.partition("=")
        config[key] = value

    print(f"Config: {', '.join(f'{k}={v}' for k, v in config.items())}")
    changed = render(config, dry_run=args.dry_run)
    action = "would update" if args.dry_run else "updated"
    print(f"Done — {changed} file(s) {action}.")


if __name__ == "__main__":
    main()
