# flagrot

> A CLI auditor that discovers feature flags across code and config, tracks their usage and ownership, and reports expired, stale, or cleanup-ready flags.

[![CI](https://github.com/justiceandmercy/flagrot/actions/workflows/ci.yml/badge.svg)](https://github.com/justiceandmercy/flagrot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Topics:** feature-flags, cli, code-quality, static-analysis, python, developer-tools

## Features

- Discover feature flags from source code, environment defaults, and JSON, YAML, or TOML configuration files using configurable adapters.
- Normalize flags into a typed model with name, owner, created date, expiry date, default value, and rollout metadata.
- Map each flag to every source usage with file, line, and enclosing function or class context.
- Detect expired flags, flags past their removal date, and flags whose default value makes the flag effectively dead.
- Flag stale or unused flags that have no production references or only test references.
- Resolve ownership and age from Git blame and commit history when metadata is missing.
- Support ignore directives and per-path exclusions for generated or vendored code.
- Emit human-readable, JSON, and SARIF reports for local use and CI integration.
- Create and compare baselines so teams can prevent new flag debt without blocking legacy flags.
- Provide init and explain commands to generate configuration and diagnose a single flag.
- Return non-zero exit codes for policy violations with configurable severity thresholds.
- Load project settings from .flagrot.toml with schema validation and helpful errors.

## Install

```sh
git clone https://github.com/justiceandmercy/flagrot.git
cd flagrot
pip install .
```

## Quick start

```sh
flagrot --help
```

Entry point: `src/main.py`.

## Architecture

- `src/main.py` — CLI entrypoint defining scan, report, init, explain, and baseline subcommands with argument parsing and exit-code handling.
- `src/config.py` — Loads and validates .flagrot.toml, resolves defaults, path filters, rule thresholds, and reporter settings.
- `src/models.py` — Defines immutable dataclasses for Flag, FlagUsage, Finding, and ScanResult with serialization helpers.
- `src/discovery.py` — Discovers flags from code and configuration using provider adapters and configurable regular expressions.
- `src/usage.py` — Scans source trees for flag references and attaches file, line, and contextual metadata to each usage.
- `src/rules.py` — Implements expiry, staleness, ownership, and dead-default checks, producing severity-ranked findings.
- `src/gitinfo.py` — Queries Git blame and history to infer flag age, last modification, and likely owner.
- `src/reporters.py` — Renders scan results as text, JSON, and SARIF with stable finding fingerprints.
- `src/baseline.py` — Creates, reads, and compares baseline files so only new findings fail CI.
- `src/flagrot/__init__.py` — Exposes the public Python API for embedding flag discovery and rule evaluation in other tools.
- `tests/test_discovery.py` — Tests flag extraction from representative code and config fixtures, including edge cases and ignore directives.
- `tests/test_rules.py` — Tests expiry, staleness, ownership, and baseline comparison logic with deterministic fixtures.
- `pyproject.toml` — Declares package metadata, dependencies, console script entry point, and test configuration.
- `README.md` — Documents installation, quick start, configuration, CI usage, and report formats.
- `docs/config.md` — Reference for every .flagrot.toml option, adapter, rule, and severity threshold.

For the full module map and design decisions, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing

```sh
pytest -q
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome!

## License

MIT — see [LICENSE](LICENSE).
