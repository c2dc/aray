"""Backwards-compatible entry point. Prefer: uv run aray (via [project.scripts])."""
from aray.cli import main

if __name__ == "__main__":
    main()
