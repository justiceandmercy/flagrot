"""Smoke test: the project must be importable and self-consistent."""

import importlib
import sys
from pathlib import Path


def test_project_is_importable():
    root = Path(__file__).resolve().parent.parent
    assert (root / "pyproject.toml").exists(), "pyproject.toml missing"
    sys.path.insert(0, str(root / "src"))
    importlib.import_module("main")


def test_entrypoint_callable():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from main import run
    assert callable(run)
