"""Backwards-compatible entry point. Prefer: uv run aray-eval (via [project.scripts])."""
from aray.evaluator import main

if __name__ == "__main__":
    main()
