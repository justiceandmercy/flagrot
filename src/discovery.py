from __future__ import annotations

import ast
import configparser
import fnmatch
import json
import os
import re
import subprocess
import tomllib
from dataclasses import replace as dataclass_replace
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None

yaml = _yaml

from .config import Config
from .models import Flag, FlagUsage

CONTAINER_KEYS = {"flags", "feature_flags", "featureflags", "features", "toggles"}


def _parse_date(value: Any) -> Any:
    from datetime import date

    if value is None or isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _looks_like_flag(key: Any) -> bool:
    if not isinstance(key, str) or not key or key.lower() in CONTAINER_KEYS:
        return False
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,}", key):
        return False
    lowered = key.lower()
    return key.isupper() or any(token in lowered for token in ("flag", "feature", "toggle", "enable"))


def _merge_flag(existing: Flag, new: Flag) -> Flag:
    default = existing.default
    if default is None and new.default is not None:
        default = new.default
    rollout = existing.rollout if existing.rollout is not None else new.rollout
    metadata = {**new.metadata, **existing.metadata}
    return Flag(
        name=existing.name,
        owner=existing.owner or new.owner,
        created=existing.created or new.created,
        expiry=existing.expiry or new.expiry,
        default=default,
        rollout=rollout,
        source=existing.source or new.source,
        metadata=metadata,
    )


def _add_flag(flags_by_name: dict[str, Flag], flag: Flag) -> None:
    if flag.name in flags_by_name:
        flags_by_name[flag.name] = _merge_flag(flags_by_name[flag.name], flag)
    else:
        flags_by_name[flag.name] = flag


def iter_files(root: Path, config: Config):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not config.is_excluded(Path(dirpath) / d)]
        for filename in filenames:
            path = Path(dirpath) / filename
            if config.is_excluded(path):
                continue
            try:
                if path.stat().st_size > config.max_file_size:
                    continue
            except OSError:
                continue
            try:
                with path.open("rb") as handle:
                    sample = handle.read(1024)
                if b"\0" in sample:
                    continue
            except OSError:
                continue
            yield path


def python_context_map(path: Path, lines: list[str]) -> dict[int, str]:
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        return {}
    ranges: list[tuple[int, int, int, str]] = []

    def visit(node: ast.AST, depth: int) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            end = getattr(node, "end_lineno", node.lineno)
            ranges.append((depth, node.lineno, end, f"{kind} {node.name}"))
        for child in ast.iter_child_nodes(node):
            visit(child, depth + 1)

    visit(tree, 0)
    mapping: dict[int, str] = {}
    for lineno in range(1, len(lines) + 1):
        candidates = [item for item in ranges if item[1] <= lineno <= item[2]]
        if candidates:
            candidates.sort(key=lambda item: item[0])
            mapping[lineno] = candidates[-1][3]
    return mapping


def generic_context(lines: list[str], lineno: int) -> str:
    for index in range(lineno - 2, -1, -1):
        match = re.match(r"\s*(?:def|class|function|func)\s+([A-Za-z_]\w*)", lines[index])
        if match:
            keyword = lines[index].lstrip().split(None, 1)[0]
            return f"{keyword} {match.group(1)}"
    return ""


def _make_usage(flag_name: str, path: Path | str, line: int, context: str, kind: str, snippet: str) -> FlagUsage:
    return FlagUsage(
        flag_name=flag_name,
        path=str(path),
        line=line,
        context=context,
        kind=kind,
        snippet=snippet.strip(),
    )


def _extract_scalar(value: Any) -> Any:
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true", "false"}:
            return low == "true"
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value.strip()
    return value


def _make_config_flag(name: str, value: Any, path: Path | str) -> tuple[Flag, FlagUsage]:
    owner = None
    created = None
    expiry = None
    default = value
    rollout = None
    metadata: dict[str, Any] = {}
    if isinstance(value, dict):
        default = value.get("default", value.get("value", value.get("enabled")))
        owner = value.get("owner") or value.get("maintainer")
        created = _parse_date(value.get("created") or value.get("created_at"))
        expiry = _parse_date(
            value.get("expiry")
            or value.get("expires")
            or value.get("removal_date")
            or value.get("remove_by")
        )
        rollout_candidate = value.get("rollout")
        if isinstance(rollout_candidate, dict):
            rollout = rollout_candidate
        elif any(k in value for k in ("percentage", "percent", "variants", "cohorts")):
            rollout = {k: value[k] for k in ("percentage", "percent", "variants", "cohorts") if k in value}
        metadata = {
            k: v
            for k, v in value.items()
            if k
            not in {
                "default",
                "value",
                "enabled",
                "owner",
                "maintainer",
                "created",
                "created_at",
                "expiry",
                "expires",
                "removal_date",
                "remove_by",
                "rollout",
                "percentage",
                "percent",
                "variants",
                "cohorts",
            }
        }
    else:
        default = _extract_scalar(value)
    flag = Flag(
        name=name,
        owner=owner,
        created=created,
        expiry=expiry,
        default=default,
        rollout=rollout,
        source=str(path),
        metadata=metadata,
    )
    usage = _make_usage(name, path, 1, "config", "config", f"{name} = {value!r}")
    return flag, usage


def _extract_mapping(data: Any, path: Path | str, flags_by_name: dict[str, Flag], usages: list[FlagUsage]) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in CONTAINER_KEYS and isinstance(value, dict):
                for child_key, child_value in value.items():
                    flag, usage = _make_config_flag(str(child_key), child_value, path)
                    _add_flag(flags_by_name, flag)
                    usages.append(usage)
                continue
            if _looks_like_flag(key):
                flag, usage = _make_config_flag(str(key), value, path)
                _add_flag(flags_by_name, flag)
                usages.append(usage)
                continue
            _extract_mapping(value, path, flags_by_name, usages)
    elif isinstance(data, list):
        for item in data:
            _extract_mapping(item, path, flags_by_name, usages)


def _parse_env_file(path: Path, flags_by_name: dict[str, Flag], usages: list[FlagUsage]) -> None:
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not _looks_like_flag(key):
            continue
        value = value.strip().strip('"').strip("'")
        flag, _ = _make_config_flag(key, value, path)
        usage = _make_usage(key, path, line_number, "env", "config", raw_line.strip())
        _add_flag(flags_by_name, flag)
        usages.append(usage)


def _parse_ini_file(path: Path, flags_by_name: dict[str, Flag], usages: list[FlagUsage]) -> None:
    parser = configparser.ConfigParser()
    try:
        parser.read(path)
    except configparser.Error:
        return
    for section in parser.sections():
        for key, value in parser.items(section):
            if not _looks_like_flag(key):
                continue
            flag, _ = _make_config_flag(key, value, path)
            usage = _make_usage(key, path, 1, f"ini:{section}", "config", f"{key} = {value}")
            _add_flag(flags_by_name, flag)
            usages.append(usage)


class CodeAdapter:
    def discover(self, path: Path, config: Config, root: Path) -> tuple[list[Flag], list[FlagUsage]]:
        if config.is_config_file(path):
            return [], []
        flags_by_name: dict[str, Flag] = {}
        usages: list[FlagUsage] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], []
        lines = text.splitlines()
        context_map = python_context_map(path, lines) if path.suffix.lower() == ".py" else {}
        ignore_next = False
        for line_number, line in enumerate(lines, 1):
            if ignore_next:
                ignore_next = False
                continue
            if config.ignore_directive in line:
                if "next" in line.lower():
                    ignore_next = True
                continue
            for pattern in config.code_patterns:
                try:
                    compiled = re.compile(pattern)
                except re.error:
                    continue
                for match in compiled.finditer(line):
                    captured = bool(match.groups())
                    name = match.group(1) if captured else match.group(0)
                    if not name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,}", name):
                        continue
                    if not captured and not _looks_like_flag(name):
                        continue
                    context = context_map.get(line_number) or generic_context(lines, line_number)
                    kind = "test" if config.is_test_path(path) else "code"
                    usages.append(_make_usage(name, path, line_number, context, kind, line))
                    _add_flag(flags_by_name, Flag(name=name, source=f"{path}:{line_number}"))
        return list(flags_by_name.values()), usages


class ConfigAdapter:
    def discover(self, path: Path, config: Config, root: Path) -> tuple[list[Flag], list[FlagUsage]]:
        if not config.is_config_file(path):
            name = path.name.lower()
            if not any(fnmatch.fnmatch(name, pattern) for pattern in config.env_files):
                return [], []
        flags_by_name: dict[str, Flag] = {}
        usages: list[FlagUsage] = []
        suffix = path.suffix.lower()
        name = path.name.lower()
        try:
            if suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                _extract_mapping(data, path, flags_by_name, usages)
            elif suffix == ".toml":
                with path.open("rb") as handle:
                    data = tomllib.load(handle)
                _extract_mapping(data, path, flags_by_name, usages)
            elif suffix in {".yaml", ".yml"}:
                if yaml is None:
                    return [], []
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if data is not None:
                    _extract_mapping(data, path, flags_by_name, usages)
            elif suffix in {".ini", ".cfg"}:
                _parse_ini_file(path, flags_by_name, usages)
            elif any(fnmatch.fnmatch(name, pattern) for pattern in config.env_files):
                _parse_env_file(path, flags_by_name, usages)
            else:
                return [], []
        except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError):
            return [], []
        return list(flags_by_name.values()), usages


def resolve_git_metadata(root: Path, flag: Flag, usages: list[FlagUsage], config: Config) -> Flag:
    if not config.git_metadata or (flag.owner and flag.created):
        return flag
    candidate = usages[0].path if usages else (flag.source.split(":", 1)[0] if flag.source else None)
    if not candidate:
        return flag
    path = Path(candidate)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        relative = path.name
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%an%x1f%aI", "--", relative],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return flag
    if result.returncode != 0 or not result.stdout.strip():
        return flag
    parts = result.stdout.strip().split("\x1f", 1)
    owner = flag.owner or (parts[0].strip() if parts and parts[0].strip() else None)
    created = flag.created
    if created is None and len(parts) == 2:
        created = _parse_date(parts[1].strip())
    return dataclass_replace(flag, owner=owner, created=created)


def discover(root: Path | str, config: Config) -> tuple[list[Flag], list[FlagUsage]]:
    root = Path(root).resolve()
    flags_by_name: dict[str, Flag] = {}
    all_usages: list[FlagUsage] = []
    for path in iter_files(root, config):
        if not config.is_included(path):
            continue
        for adapter in (CodeAdapter(), ConfigAdapter()):
            flags, usages = adapter.discover(path, config, root)
            for flag in flags:
                _add_flag(flags_by_name, flag)
            all_usages.extend(usages)
    flags = list(flags_by_name.values())
    if config.git_metadata:
        flags = [
            resolve_git_metadata(root, flag, [usage for usage in all_usages if usage.flag_name == flag.name], config)
            for flag in flags
        ]
    flags.sort(key=lambda item: item.name)
    all_usages.sort(key=lambda item: (item.path, item.line, item.flag_name))
    return flags, all_usages
