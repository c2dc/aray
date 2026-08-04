"""Backwards-compatible entry point. Prefer: uv run aray-normalize (via [project.scripts])."""
from aray.normalizer import main

if __name__ == "__main__":
    main()
