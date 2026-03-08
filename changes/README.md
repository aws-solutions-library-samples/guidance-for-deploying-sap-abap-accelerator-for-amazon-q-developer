# Changes Directory

Each file in this directory documents a single PR's changes. This keeps the changelog organized and avoids merge conflicts from everyone editing the same file.

## Naming Convention

```
<date>-<branch-or-slug>.md
```

- `date`: `YYYY-MM-DD` of the PR merge (or creation).
- `branch-or-slug`: Branch name or short description (e.g., `better-docker`, `fix-csrf-handling`).

Example: `2026-03-08-better-docker.md`

## Generating a Combined Changelog

To produce a single changelog from all entries (newest first):

```bash
ls -r changes/2*.md | xargs cat > CHANGELOG.md
```
