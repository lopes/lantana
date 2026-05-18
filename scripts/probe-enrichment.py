#!/usr/bin/env python3
"""Live enrichment-provider probe.

Hits each provider's real upstream API with the given payload(s) and prints
the raw HTTP response alongside the normalized EnrichmentResult.data, so the
operator can verify against each provider's web UI / docs.

Provider/input matrix:
    --ip    routes to: abuseipdb, shodan, virustotal, greynoise, phishstats
    --hash  routes to: virustotal only

Examples (all invoked from the pipeline/ directory):
    uv run python ../scripts/probe-enrichment.py --ip 212.115.85.236
    uv run python ../scripts/probe-enrichment.py --ip 1.2.3.4 \\
        --provider greynoise,phishstats
    uv run python ../scripts/probe-enrichment.py --hash 0a1b2c... \\
        --provider virustotal
    uv run python ../scripts/probe-enrichment.py --ip 1.2.3.4 \\
        --secrets ./local-secrets.json
    uv run python ../scripts/probe-enrichment.py --ip 1.2.3.4 \\
        --insecure          # local-testing workaround for broken workstation TLS
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Workstation Pythons (notably Homebrew 3.14 on macOS) often ship without a
# trust store, so live HTTPS calls fail with CERTIFICATE_VERIFY_FAILED. The
# pipeline venv always has certifi installed (httpx transitive dep), and httpx
# honours SSL_CERT_FILE. This is a no-op on production hosts where the system
# bundle resolves.  Must run *before* any TLS connection is initialized.
try:
    import certifi as _certifi

    os.environ.setdefault("SSL_CERT_FILE", _certifi.where())
except ImportError:  # pragma: no cover - certifi is a httpx dep
    pass

import httpx
import tenacity

from lantana.common.config import SecretsConfig, load_secrets_tolerant
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.greynoise import GreyNoiseProvider
from lantana.enrichment.providers.phishstats import PhishStatsProvider
from lantana.enrichment.providers.shodan import ShodanProvider
from lantana.enrichment.providers.virustotal import VirusTotalProvider

if TYPE_CHECKING:
    from lantana.enrichment.providers.base import EnrichmentResult

IP_PROVIDERS = ("abuseipdb", "shodan", "virustotal", "greynoise", "phishstats")
HASH_PROVIDERS = ("virustotal",)
ALL_PROVIDERS = ("abuseipdb", "shodan", "virustotal", "greynoise", "phishstats")


def _resolve_secrets_path(cli_path: str | None) -> Path:
    if cli_path:
        return Path(cli_path)
    env = os.environ.get("LANTANA_SECRETS_PATH")
    if env:
        return Path(env)
    return Path("/etc/lantana/collector/secrets.json")


def _load_secrets(path: Path) -> SecretsConfig:
    """Load secrets, tolerating legacy vault key names.

    Wraps ``lantana.common.config.load_secrets_tolerant`` and emits a stderr
    note when translation actually happened.
    """
    config, translated = load_secrets_tolerant(path)
    if translated:
        print(
            f"[note: {path.name} uses legacy vault key names — "
            "auto-translated to vault_<type>_<service>]",
            file=sys.stderr,
        )
    return config


def _build_provider(name: str, secrets: SecretsConfig) -> tuple[Any | None, str | None]:
    """Return (provider, disabled_reason). Exactly one of the two is None."""
    if name == "abuseipdb":
        return AbuseIPDBProvider(secrets.abuseipdb), None
    if name == "shodan":
        return ShodanProvider(secrets.shodan), None
    if name == "virustotal":
        return VirusTotalProvider(secrets.virustotal), None
    if name == "greynoise":
        if secrets.greynoise is None:
            return None, "secrets.greynoise is null"
        return GreyNoiseProvider(secrets.greynoise), None
    if name == "phishstats":
        if secrets.phishstats is None:
            return None, "secrets.phishstats is null"
        return PhishStatsProvider(secrets.phishstats), None
    raise ValueError(f"unknown provider: {name}")


def _attach_capture(provider: Any) -> dict[str, object]:
    """Attach an httpx response hook to provider._client. Returns the captured dict.

    The hook overwrites the dict on every response, so after the call returns we
    hold whatever the provider last received from upstream — including the error
    body for HTTP 4xx/5xx, since hooks fire before raise_for_status().
    """
    captured: dict[str, object] = {}

    async def _capture(resp: httpx.Response) -> None:
        await resp.aread()
        captured["status"] = resp.status_code
        try:
            captured["body"] = resp.json()
        except (ValueError, json.JSONDecodeError):
            captured["body"] = resp.text

    provider._client.event_hooks.setdefault("response", []).append(_capture)
    return captured


def _print_block(
    provider_name: str,
    payload: str,
    captured: dict[str, object],
    normalized: EnrichmentResult | None,
    error: str | None,
    show_raw: bool,
) -> None:
    print(f"=== {provider_name} // {payload} ===")
    if show_raw and captured:
        status = captured.get("status", "?")
        print(f"[raw API response] (HTTP {status})")
        body = captured.get("body")
        if isinstance(body, (dict, list)):
            print(json.dumps(body, indent=2, default=str))
        else:
            print(str(body))
        print()
    if error is not None:
        print(f"[error] {error}")
    elif normalized is not None:
        print("[normalized EnrichmentResult.data]")
        print(json.dumps(normalized.data, indent=2, default=str))
    print()


async def _probe_one(
    provider_name: str,
    kind: str,
    payload: str,
    secrets: SecretsConfig,
    show_raw: bool,
    insecure: bool,
) -> bool:
    """Probe a single (provider, payload) pair. Returns True on success."""
    provider, disabled = _build_provider(provider_name, secrets)
    if disabled is not None:
        print(f"=== {provider_name} // {payload} ===")
        print(f"[disabled — {disabled}]\n")
        return True

    assert provider is not None
    if insecure:
        # Replace the provider's client with one that skips TLS verification.
        # Only useful for local workstations where the system trust store is
        # broken and Python's ssl module can't validate cert chains.
        await provider._client.aclose()
        provider._client = httpx.AsyncClient(timeout=30.0, verify=False)
    captured = _attach_capture(provider)
    try:
        if provider_name == "virustotal" and kind == "hash":
            normalized = await provider.enrich_hash(payload)
        else:
            normalized = await provider.enrich_ip(payload)
        _print_block(provider_name, payload, captured, normalized, None, show_raw)
        return True
    except httpx.HTTPStatusError as exc:
        msg = f"HTTPStatusError {exc.response.status_code}: {exc!s}"
        _print_block(provider_name, payload, captured, None, msg, show_raw)
        return False
    except tenacity.RetryError as exc:
        # Tenacity wraps the underlying error in a Future. Unwrap so the
        # operator sees the actual status / exception instead of "<Future ...>".
        underlying = exc.last_attempt.exception() if exc.last_attempt else None
        if isinstance(underlying, httpx.HTTPStatusError):
            msg = (
                f"HTTPStatusError {underlying.response.status_code} (after retries): "
                f"{underlying!s}"
            )
        elif underlying is not None:
            msg = f"{type(underlying).__name__} (after retries): {underlying!s}"
        else:
            msg = f"RetryError (after retries): {exc!s}"
        _print_block(provider_name, payload, captured, None, msg, show_raw)
        return False
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc!s}"
        _print_block(provider_name, payload, captured, None, msg, show_raw)
        return False
    finally:
        await provider.close()


async def _run(args: argparse.Namespace) -> int:
    secrets_path = _resolve_secrets_path(args.secrets)
    if not secrets_path.exists():
        print(f"error: secrets file not found: {secrets_path}", file=sys.stderr)
        print("       pass --secrets <path> or set LANTANA_SECRETS_PATH", file=sys.stderr)
        return 2
    try:
        secrets = _load_secrets(secrets_path)
    except Exception as exc:
        print(f"error: failed to parse {secrets_path}: {exc}", file=sys.stderr)
        return 2

    # Flatten --provider entries: argparse gives a list of strings, each of which
    # may itself be comma-separated.
    raw_provider_args = args.provider or ["all"]
    flat: list[str] = []
    for entry in raw_provider_args:
        flat.extend(p.strip() for p in entry.split(",") if p.strip())

    explicit_all = "all" in flat
    if explicit_all:
        chosen = list(ALL_PROVIDERS)
    else:
        unknown = [p for p in flat if p not in ALL_PROVIDERS]
        if unknown:
            print(f"error: unknown provider(s): {unknown}", file=sys.stderr)
            return 2
        chosen = flat

    if not args.ip and not args.hash:
        print("error: at least one --ip or --hash is required", file=sys.stderr)
        return 2

    all_ok = True
    show_raw = not args.no_raw
    insecure = bool(args.insecure)

    if insecure:
        print(
            "!! TLS verification disabled (--insecure) — local testing only, "
            "never use in production",
            file=sys.stderr,
        )

    for ip in args.ip:
        for name in chosen:
            if name not in IP_PROVIDERS:
                continue
            ok = await _probe_one(name, "ip", ip, secrets, show_raw=show_raw, insecure=insecure)
            all_ok = all_ok and ok

    for digest in args.hash:
        for name in chosen:
            if name in HASH_PROVIDERS:
                ok = await _probe_one(
                    name, "hash", digest, secrets, show_raw=show_raw, insecure=insecure,
                )
                all_ok = all_ok and ok
            elif not explicit_all:
                # Operator explicitly named a provider that doesn't take hashes.
                print(f"=== {name} // {digest} ===")
                print(f"[skipped — {name} does not accept file hashes]\n")

    return 0 if all_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Probe each Lantana enrichment provider with a live payload and print "
            "the raw upstream response alongside the normalized EnrichmentResult."
        ),
    )
    parser.add_argument(
        "--ip", action="append", default=[],
        help="IP address to enrich (IPv4 or IPv6). Repeatable.",
    )
    parser.add_argument(
        "--hash", action="append", default=[], dest="hash",
        help="SHA256 file hash to enrich (VirusTotal only). Repeatable.",
    )
    parser.add_argument(
        "--provider", action="append", default=None,
        help="Provider name, or 'all'. Comma-separated values accepted. "
             "Repeatable. Default: all.",
    )
    parser.add_argument(
        "--secrets", default=None,
        help="Path to secrets.json. Default: $LANTANA_SECRETS_PATH or "
             "/etc/lantana/collector/secrets.json",
    )
    parser.add_argument(
        "--no-raw", action="store_true",
        help="Suppress the raw upstream response — only print the normalized fields.",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Skip TLS certificate verification. ONLY for local testing on a "
             "workstation whose Python trust store is broken — never use in "
             "production. Prints a loud warning when active.",
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
