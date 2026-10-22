# Architecture

flagrot — A CLI auditor that discovers feature flags across code and config, tracks their usage and ownership, and reports expired, stale, or cleanup-ready flags.

## Overview

The codebase is organized around a small set of focused modules. Each module owns a
single responsibility and the public surface is kept deliberately small so the tool
stays easy to hack on.

## Module map

| Path | Responsibility |
| ---- | -------------- |
| `src/main.py` | CLI entrypoint defining scan, report, init, explain, and baseline subcommands with argument parsing and exit-code handling. |
| `src/config.py` | Loads and validates .flagrot.toml, resolves defaults, path filters, rule thresholds, and reporter settings. |
| `src/models.py` | Defines immutable dataclasses for Flag, FlagUsage, Finding, and ScanResult with serialization helpers. |
| `src/discovery.py` | Discovers flags from code and configuration using provider adapters and configurable regular expressions. |
| `src/usage.py` | Scans source trees for flag references and attaches file, line, and contextual metadata to each usage. |
| `src/rules.py` | Implements expiry, staleness, ownership, and dead-default checks, producing severity-ranked findings. |
| `src/gitinfo.py` | Queries Git blame and history to infer flag age, last modification, and likely owner. |
| `src/reporters.py` | Renders scan results as text, JSON, and SARIF with stable finding fingerprints. |
| `src/baseline.py` | Creates, reads, and compares baseline files so only new findings fail CI. |
| `src/flagrot/__init__.py` | Exposes the public Python API for embedding flag discovery and rule evaluation in other tools. |
| `tests/test_discovery.py` | Tests flag extraction from representative code and config fixtures, including edge cases and ignore directives. |
| `tests/test_rules.py` | Tests expiry, staleness, ownership, and baseline comparison logic with deterministic fixtures. |
| `pyproject.toml` | Declares package metadata, dependencies, console script entry point, and test configuration. |
| `README.md` | Documents installation, quick start, configuration, CI usage, and report formats. |
| `docs/config.md` | Reference for every .flagrot.toml option, adapter, rule, and severity threshold. |

## Key design decisions

- **Zero/low runtime dependencies**: the core works from the standard library so
  installs stay fast and supply-chain risk stays low.
- **Configuration before convention**: behavior is tunable through config files and
  documented CLI flags instead of magic environment variables.
- **Structured output modes**: human-readable text by default, machine-readable JSON
  for automation, and DOT/Mermaid exports where a graph applies.
- **Everything is guarded by tests**: the CI matrix runs the suite on every push.

## Data flow

`CLI entrypoint -> config loading -> per-item scanning/processing -> aggregation ->
reporting (text | JSON | graph)`.

## Testing

Pytest unit tests cover discovery parsing, config validation, rule evaluation, Git metadata fallbacks, baseline fingerprinting, and reporter output. Integration tests invoke the CLI against temporary repositories containing flags in code and config, verifying exit codes, ignore behavior, and SARIF/JSON schemas. Fixtures include expired, unused, owned, and unknown flags to exercise all finding types.

Run them locally with `pytest -q`. CI (`.github/workflows/ci.yml`) executes the
same suite on a version matrix for every push and pull request.
