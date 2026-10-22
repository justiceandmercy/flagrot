from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any


def _parse_date(value: Any) -> date | None:
    if value is None or isinstance(value, date):
        return value  # type: ignore[return-value]
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _date_to_str(value: date | None) -> str | None:
    return value.isoformat() if value is not None else None


@dataclass(frozen=True)
class Flag:
    """A normalized feature flag."""

    name: str
    owner: str | None = None
    created: date | None = None
    expiry: date | None = None
    default: Any = None
    rollout: dict[str, Any] | None = None
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "owner": self.owner,
            "created": _date_to_str(self.created),
            "expiry": _date_to_str(self.expiry),
            "default": self.default,
            "rollout": self.rollout,
            "source": self.source,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Flag":
        return cls(
            name=str(data["name"]),
            owner=data.get("owner"),
            created=_parse_date(data.get("created")),
            expiry=_parse_date(data.get("expiry")),
            default=data.get("default"),
            rollout=data.get("rollout"),
            source=str(data.get("source", "")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class FlagUsage:
    """A single source reference to a feature flag."""

    flag_name: str
    path: str
    line: int
    column: int = 0
    context: str = ""
    kind: str = "code"
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "flag_name": self.flag_name,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "context": self.context,
            "kind": self.kind,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlagUsage":
        return cls(
            flag_name=str(data["flag_name"]),
            path=str(data["path"]),
            line=int(data.get("line", 0)),
            column=int(data.get("column", 0)),
            context=str(data.get("context", "")),
            kind=str(data.get("kind", "code")),
            snippet=str(data.get("snippet", "")),
        )


@dataclass(frozen=True)
class Finding:
    """A policy or quality finding for a flag."""

    flag_name: str
    rule: str
    severity: str
    message: str
    path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "flag_name": self.flag_name,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            flag_name=str(data["flag_name"]),
            rule=str(data["rule"]),
            severity=str(data["severity"]),
            message=str(data["message"]),
            path=data.get("path"),
            line=data.get("line"),
        )


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning a project."""

    root: str
    config_path: str | None = None
    flags: tuple[Flag, ...] = ()
    usages: tuple[FlagUsage, ...] = ()
    findings: tuple[Finding, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "config_path": self.config_path,
            "flags": [flag.to_dict() for flag in self.flags],
            "usages": [usage.to_dict() for usage in self.usages],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def counts(self) -> dict[str, int]:
        return {
            "flags": len(self.flags),
            "usages": len(self.usages),
            "findings": len(self.findings),
        }
