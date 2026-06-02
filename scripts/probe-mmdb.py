#!/usr/bin/env python3
"""Live MMDB probe for MaxMind GeoLite2 enrichment.

Exercises the same flow Ansible runs at deploy time: downloads the City + ASN
tarballs from MaxMind, extracts the `.mmdb` files, then looks up IPs against
them and prints both the raw MaxMind record and the exact ``.geo.*`` fields
Vector's VRL would emit into bronze.

If the MMDB files already exist at ``--mmdb-dir``, the download step is
skipped — useful on the collector after a real deploy. ``--force-download``
re-fetches even when files are present (matches the monthly cron behaviour).

The license key is read from ``secrets.json``'s ``vault_apikey_maxmind`` field
— same interface as ``probe-enrichment.py``. Use ``--secrets`` to point at a
non-default file (e.g. a hand-written workstation copy).

Default MMDB directory:
    Collector (production):  /var/lib/lantana/collector/geoip (when it exists)
    Workstation / test env:  /tmp/lantana/mmdb (auto-fallback)
    Explicit override:       pass --mmdb-dir <path>

Examples (invoked from the pipeline/ directory):
    # Workstation — defaults fall back to /tmp/lantana/mmdb
    uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \\
        --secrets ./local-secrets.json

    # Query-only on the collector (MMDBs already present)
    uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8

    # Multiple IPs, custom directory
    uv run python ../scripts/probe-mmdb.py --ip 1.1.1.1 --ip 64.239.123.129 \\
        --mmdb-dir ~/lantana-mmdb --secrets ./local-secrets.json

    # Force refresh (re-download even though files exist)
    uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \\
        --secrets ./local-secrets.json --force-download

    # Workstation TLS workaround (Homebrew Python 3.14 cert chain issue)
    uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \\
        --secrets ./local-secrets.json --insecure

Fields emitted (mirrors ``profile_collector/templates/receive.vector.yaml.j2``):
    geo.country_code, geo.region_code, geo.city,
    geo.latitude, geo.longitude, geo.timezone,
    geo.asn, geo.isp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

# Workstation Pythons (notably Homebrew 3.14 on macOS) often ship without a
# trust store. Same fix as probe-enrichment.py. No-op on production hosts.
try:
    import certifi as _certifi

    os.environ.setdefault("SSL_CERT_FILE", _certifi.where())
except ImportError:  # pragma: no cover
    pass

import httpx
import maxminddb

from lantana.common.config import SecretsConfig, load_secrets_tolerant

DEFAULT_MMDB_DIR = Path("/var/lib/lantana/collector/geoip")
WORKSTATION_FALLBACK_DIR = Path("/tmp/lantana/mmdb")
DEFAULT_SECRETS_PATH = Path("/etc/lantana/collector/secrets.json")
CITY_DB_NAME = "GeoLite2-City.mmdb"
ASN_DB_NAME = "GeoLite2-ASN.mmdb"

EDITIONS = (
    ("GeoLite2-City", CITY_DB_NAME),
    ("GeoLite2-ASN", ASN_DB_NAME),
)
DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={key}&suffix=tar.gz"
)


def _resolve_mmdb_dir(cli_path: str | None) -> tuple[Path, bool]:
    """Pick the MMDB directory and tell the caller if we fell back.

    Priority: explicit ``--mmdb-dir`` > collector path (if it already exists)
    > workstation fallback at ``/tmp/lantana/mmdb``. The fallback is signalled
    so the caller can print a stderr note — operators see immediately whether
    they're hitting the production path or the test path.
    """
    if cli_path:
        return Path(cli_path).expanduser(), False
    if DEFAULT_MMDB_DIR.exists():
        return DEFAULT_MMDB_DIR, False
    return WORKSTATION_FALLBACK_DIR, True


def _resolve_secrets_path(cli_path: str | None) -> Path:
    if cli_path:
        return Path(cli_path).expanduser()
    env = os.environ.get("LANTANA_SECRETS_PATH")
    if env:
        return Path(env)
    return DEFAULT_SECRETS_PATH


def _load_secrets(path: Path) -> SecretsConfig:
    """Load secrets, tolerating legacy vault key names.

    Mirrors ``probe-enrichment.py``'s helper. Emits a stderr note if the file
    used legacy ``vault_<service>_*_key`` names so the operator knows the
    canonical convention has changed.
    """
    config, translated = load_secrets_tolerant(path)
    if translated:
        print(
            f"[note: {path.name} uses legacy vault key names — "
            "auto-translated to vault_<type>_<service>]",
            file=sys.stderr,
        )
    return config


def _download_edition(
    client: httpx.Client,
    edition: str,
    mmdb_name: str,
    license_key: str,
    dest_dir: Path,
) -> None:
    """Download one MaxMind tarball and extract its .mmdb into dest_dir.

    Mirrors the Ansible role's `get_url` + `tar -xzf ... --wildcards '*.mmdb'
    --strip-components=1` so the on-disk result is byte-identical to a
    production deploy.
    """
    url = DOWNLOAD_URL.format(edition=edition, key=license_key)
    print(f"[download] {edition} from MaxMind ...", file=sys.stderr)
    response = client.get(url, follow_redirects=True)
    if response.status_code == 401:
        raise RuntimeError(
            f"MaxMind rejected the license key for {edition} (HTTP 401). "
            "Confirm the key is active and your account email is verified."
        )
    response.raise_for_status()

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp.write(response.content)
        tarball_path = Path(tmp.name)

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            extracted = False
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith(".mmdb"):
                    # Flatten — MaxMind tarballs nest under e.g.
                    # GeoLite2-City_20260512/GeoLite2-City.mmdb
                    member.name = Path(member.name).name
                    tar.extract(member, path=dest_dir, filter="data")
                    size_mb = (dest_dir / member.name).stat().st_size / (1024 * 1024)
                    print(
                        f"[download] wrote {dest_dir / member.name} ({size_mb:.1f} MB)",
                        file=sys.stderr,
                    )
                    extracted = True
                    break
            if not extracted:
                raise RuntimeError(
                    f"No .mmdb file found inside the {edition} tarball — "
                    "MaxMind may have changed its packaging."
                )
    finally:
        tarball_path.unlink(missing_ok=True)

    expected = dest_dir / mmdb_name
    if not expected.exists():
        raise RuntimeError(
            f"Extracted .mmdb does not match the expected name {mmdb_name!r}; "
            f"check the tarball contents."
        )


def _ensure_mmdbs(
    mmdb_dir: Path,
    license_key: str | None,
    force: bool,
    insecure: bool,
) -> int:
    """Make sure both MMDBs exist at mmdb_dir, downloading if needed.

    Returns 0 on success, non-zero on failure (already printed an error).
    """
    city_path = mmdb_dir / CITY_DB_NAME
    asn_path = mmdb_dir / ASN_DB_NAME

    if city_path.exists() and asn_path.exists() and not force:
        return 0

    if not license_key:
        missing = [str(p) for p in (city_path, asn_path) if not p.exists()]
        print(
            f"error: MMDB file(s) not found: {', '.join(missing)}",
            file=sys.stderr,
        )
        print(
            "       point --secrets at a secrets.json containing "
            "vault_apikey_maxmind to download them, or --mmdb-dir at an "
            "existing populated directory.",
            file=sys.stderr,
        )
        return 2

    if insecure:
        print(
            "!! TLS verification disabled (--insecure) — local testing only, "
            "never use in production",
            file=sys.stderr,
        )

    mmdb_dir.mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(timeout=60.0, verify=not insecure) as client:
            for edition, mmdb_name in EDITIONS:
                target = mmdb_dir / mmdb_name
                if target.exists() and not force:
                    print(
                        f"[download] {edition} already present — skipping",
                        file=sys.stderr,
                    )
                    continue
                _download_edition(client, edition, mmdb_name, license_key, mmdb_dir)
    except httpx.HTTPError as exc:
        print(f"error: download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def _vector_geo_fields(
    city: dict[str, Any] | None,
    asn: dict[str, Any] | None,
) -> dict[str, str | float | int | None]:
    """Replicate the VRL transform in receive.vector.yaml.j2 exactly.

    Vector's `get(record, [path]) ?? default` semantics: missing keys produce
    "" for strings, null for numbers. We mirror that so the probe output
    matches what an operator will see in bronze NDJSON.
    """
    city = city or {}
    asn = asn or {}

    country = city.get("country") or {}
    subdivs = city.get("subdivisions") or [{}]
    first_subdiv = subdivs[0] if subdivs else {}
    city_block = city.get("city") or {}
    location = city.get("location") or {}

    return {
        "geo.country_code": country.get("iso_code", "") or "",
        "geo.region_code": first_subdiv.get("iso_code", "") or "",
        "geo.city": (city_block.get("names") or {}).get("en", "") or "",
        "geo.latitude": location.get("latitude"),
        "geo.longitude": location.get("longitude"),
        "geo.timezone": location.get("time_zone", "") or "",
        "geo.asn": asn.get("autonomous_system_number"),
        "geo.isp": asn.get("autonomous_system_organization", "") or "",
    }


def _probe_one(
    ip: str,
    city_reader: maxminddb.Reader,
    asn_reader: maxminddb.Reader,
    show_raw: bool,
) -> bool:
    """Probe a single IP. Returns True on a clean lookup (even if no record)."""
    print(f"=== mmdb // {ip} ===")
    try:
        city_record = city_reader.get(ip)
        asn_record = asn_reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError) as exc:
        print(f"[error] {type(exc).__name__}: {exc}\n")
        return False

    if city_record is None and asn_record is None:
        print(f"[note: {ip} is not in either MMDB — Vector would emit empty .geo.* fields]\n")
        return True

    if show_raw:
        print("[raw MaxMind record — City]")
        if city_record is None:
            print("(not in GeoLite2-City)")
        else:
            print(json.dumps(city_record, indent=2, ensure_ascii=False, default=str))
        print()
        print("[raw MaxMind record — ASN]")
        if asn_record is None:
            print("(not in GeoLite2-ASN)")
        else:
            print(json.dumps(asn_record, indent=2, ensure_ascii=False, default=str))
        print()

    print("[normalized geo.* fields (matches Vector's VRL output)]")
    fields = _vector_geo_fields(
        city_record if isinstance(city_record, dict) else None,
        asn_record if isinstance(asn_record, dict) else None,
    )
    print(json.dumps(fields, indent=2, ensure_ascii=False))
    print()
    return True


def _run(args: argparse.Namespace) -> int:
    if not args.ip:
        print("error: at least one --ip is required", file=sys.stderr)
        return 2

    mmdb_dir, used_fallback = _resolve_mmdb_dir(args.mmdb_dir)
    if used_fallback:
        print(
            f"[note: using workstation default {mmdb_dir} "
            f"(production path {DEFAULT_MMDB_DIR} does not exist)]",
            file=sys.stderr,
        )
    city_path = mmdb_dir / CITY_DB_NAME
    asn_path = mmdb_dir / ASN_DB_NAME

    # Only load secrets when we actually need the license key — i.e. when a
    # download would occur. This keeps query-only runs on a populated mmdb-dir
    # working without any secrets.json present at all.
    need_download = not (city_path.exists() and asn_path.exists()) or args.force_download
    license_key: str | None = None
    if need_download:
        secrets_path = _resolve_secrets_path(args.secrets)
        if not secrets_path.exists():
            print(
                f"error: MMDB(s) missing and secrets file not found: {secrets_path}",
                file=sys.stderr,
            )
            print(
                "       pass --secrets <path> to point at a secrets.json with "
                "vault_apikey_maxmind, or --mmdb-dir <path> at an existing "
                "populated directory.",
                file=sys.stderr,
            )
            return 2
        try:
            secrets = _load_secrets(secrets_path)
        except Exception as exc:
            print(f"error: failed to parse {secrets_path}: {exc}", file=sys.stderr)
            return 2
        license_key = secrets.maxmind
        if not license_key:
            print(
                f"error: vault_apikey_maxmind missing/empty in {secrets_path}",
                file=sys.stderr,
            )
            print(
                "       MaxMind requires a license key to download GeoLite2.",
                file=sys.stderr,
            )
            return 2

    ensure_rc = _ensure_mmdbs(
        mmdb_dir,
        license_key,
        force=args.force_download,
        insecure=args.insecure,
    )
    if ensure_rc != 0:
        return ensure_rc

    all_ok = True
    show_raw = not args.no_raw

    with (
        maxminddb.open_database(str(city_path)) as city_reader,
        maxminddb.open_database(str(asn_path)) as asn_reader,
    ):
        for ip in args.ip:
            ok = _probe_one(ip, city_reader, asn_reader, show_raw=show_raw)
            all_ok = all_ok and ok

    return 0 if all_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Probe MaxMind GeoLite2 end-to-end: download MMDBs if missing "
            "(license key read from secrets.json), then look up IPs and print "
            "the raw record + the .geo.* fields Vector would emit."
        ),
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help="IP to enrich. Repeatable.",
    )
    parser.add_argument(
        "--mmdb-dir",
        default=None,
        help=f"Directory containing (or to receive) GeoLite2-City.mmdb and "
        f"GeoLite2-ASN.mmdb. Default: {DEFAULT_MMDB_DIR} on the collector "
        f"(when it exists), {WORKSTATION_FALLBACK_DIR} otherwise.",
    )
    parser.add_argument(
        "--secrets",
        default=None,
        help=f"Path to secrets.json containing vault_apikey_maxmind. Only "
        f"consulted when an MMDB needs to be downloaded. Default: "
        f"$LANTANA_SECRETS_PATH or {DEFAULT_SECRETS_PATH}",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Re-download MMDBs even if they exist (mirrors the monthly cron). "
        "Requires vault_apikey_maxmind in secrets.json.",
    )
    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="Suppress raw MaxMind records — only print the normalized geo.* fields.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS verification during the MMDB download. ONLY for local "
        "testing on a workstation whose Python trust store is broken.",
    )

    args = parser.parse_args()
    sys.exit(_run(args))


if __name__ == "__main__":
    main()
