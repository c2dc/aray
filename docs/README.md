# Documentation layout

The documentation tree separates published website inputs from build-only and
authoring files:

- `site/` contains Markdown pages and static assets published by MkDocs.
- `theme/` contains MkDocs Material Jinja overrides used during the build but
  not copied into the published website.
- `sources/` contains editable diagram sources and asset provenance records
  that are retained in the repository but not published by MkDocs.

The generated website is written to the repository-level `site/` directory.
That directory is ignored by Git and should not be edited manually.

Build the website from the repository root:

```bash
uv run mkdocs build --strict
```
