from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when configuration is invalid."""


DEFAULT_INCLUDE = ("**/*",)
DEFAULT_EXCLUDE = (
    ".git/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "__pycache__/**",
    ".venv/**",
    "*.pyc",
)
DEFAULT_TEST_PATTERNS = (
    "**/test*/**",
    "**/*_test.py",
    "**/tests/**",
    "**/test_*.py",
)
DEFAULT_CODE_PATTERNS = (
    r"\b(?:FEATURE|FLAG|ENABLE|USE)_[A-Z0-9_]{2,}\b",
    r"\bfeature_flags?\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
)
DEFAULT_ENV_FILES = (".env", ".env.*", "*.env")
DEFAULT_CONFIG_EXTENSIONS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg")
DEFAULT_IGNORE = "flagrot: ignore"


@dataclass(frozen=True)
class Config:
    """Validated project settings for flagrot."""

    root: Path
    config_path: Path | None
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    test_patterns: tuple[str, ...]
    code_patterns: tuple[str, ...]
    env_files: tuple[str, ...]
    config_extensions: tuple[str, ...]
    ignore_directive: str
    expired_severity: str
    stale_severity: str
    dead_default_severity: str
    fail_on: str
    report_format: str
    git_metadata: bool
    max_file_size: int = 1_000_000

    def is_excluded(self, path: Path | str) -> bool:
        try:
            rel = Path(path).resolve().relative_to(self.root).as_posix()
        except ValueError:
            rel = Path(path).as_posix()
        return any(
            fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(Path(rel).name, pattern)
            for pattern in self.exclude
        )

    def is_included(self, path: Path | str) -> bool:
        if self.is_excluded(path):
            return False
        try:
            rel = Path(path).resolve().relative_to(self.root).as_posix()
        except ValueError:
            rel = Path(path).as_posix()
        if not self.include:
            return True
        return any(fnmatch.fnmatch(rel, pattern) for pattern in self.include)

    def is_test_path(self, path: Path | str) -> bool:
        try:
            rel = Path(path).resolve().relative_to(self.root).as_posix()
        except ValueError:
            rel = Path(path).as_posix()
        return any(fnmatch.fnmatch(rel, pattern) for pattern in self.test_patterns)

    def is_config_file(self, path: Path | str) -> bool:
        return Path(path).suffix.lower() in self.config_extensions


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table")
    return value


def _string_tuple(value: Any, default: tuple[str, ...], name: str) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be an array of strings")
    return tuple(value)


def _str(value: Any, default: str, name: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _bool(value: Any, default: bool, name: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be a boolean")
    return value


def _int(value: Any, default: int, name: str) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{name} must be an integer")
    return value


def find_config(start: Path) -> Path | None:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        candidate = directory / ".flagrot.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(root: Path | str | None = None, config_path: Path | str | None = None) -> Config:
    resolved_root = Path(root or ".").resolve()
    if config_path is not None:
        path = Path(config_path).resolve()
        if not path.is_file():
            raise ConfigError(f"Configuration file not found: {path}")
    else:
        path = find_config(resolved_root)

    raw: dict[str, Any] = {}
    if path is not None:
        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Could not read {path}: {exc}") from exc

    discovery = _mapping(raw.get("discovery"), "discovery")
    rules = _mapping(raw.get("rules"), "rules")
    reporting = _mapping(raw.get("reporting"), "reporting")
    git = _mapping(raw.get("git"), "git")

    allowed_top = {"discovery", "rules", "reporting", "git"}
    unknown = set(raw) - allowed_top
    if unknown:
        raise ConfigError(f"Unknown top-level configuration sections: {', '.join(sorted(unknown))}")

    return Config(
        root=resolved_root,
        config_path=path,
        include=_string_tuple(discovery.get("include"), DEFAULT_INCLUDE, "discovery.include"),
        exclude=_string_tuple(discovery.get("exclude"), DEFAULT_EXCLUDE, "discovery.exclude"),
        test_patterns=_string_tuple(discovery.get("test_patterns"), DEFAULT_TEST_PATTERNS, "discovery.test_patterns"),
        code_patterns=_string_tuple(discovery.get("code_patterns"), DEFAULT_CODE_PATTERNS, "discovery.code_patterns"),
        env_files=_string_tuple(discovery.get("env_files"), DEFAULT_ENV_FILES, "discovery.env_files"),
        config_extensions=_string_tuple(discovery.get("config_extensions"), DEFAULT_CONFIG_EXTENSIONS, "discovery.config_extensions"),
        ignore_directive=_str(discovery.get("ignore_directive"), DEFAULT_IGNORE, "discovery.ignore_directive"),
        expired_severity=_str(rules.get("expired_severity"), "high", "rules.expired_severity"),
        stale_severity=_str(rules.get("stale_severity"), "medium", "rules.stale_severity"),
        dead_default_severity=_str(rules.get("dead_default_severity"), "low", "rules.dead_default_severity"),
        fail_on=_str(rules.get("fail_on"), "medium", "rules.fail_on"),
        report_format=_str(reporting.get("format"), "human", "reporting.format"),
        git_metadata=_bool(git.get("metadata"), True, "git.metadata"),
        max_file_size=_int(discovery.get("max_file_size"), 1_000_000, "discovery.max_file_size"),
    )
