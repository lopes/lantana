"""Tests for lantana.enrichment.allowlist — benign/shared-infra suppression and IOC verification."""

from __future__ import annotations

import pytest

from lantana.common.config import StixExportConfig
from lantana.enrichment.allowlist import (
    VERIFICATION_STATUS_SUPPRESSED,
    VERIFICATION_STATUS_UNVERIFIED,
    VERIFICATION_STATUS_VERIFIED,
    classify_static_suppression,
    evaluate_ioc_verification,
    is_shared_hosting_url,
    should_export_ioc_to_stix,
)


class TestStaticSuppression:
    @pytest.mark.parametrize(
        "ip",
        [
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "208.67.222.222",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:1.1.1.1",
            "::ffff:8.8.8.8",
        ],
    )
    def test_public_dns_resolvers_suppressed_for_c2_ip(self, ip: str) -> None:
        assert classify_static_suppression("c2_ip", ip) == "benign_resolver_ip"

    def test_public_resolver_ip_literal_url_suppressed(self) -> None:
        assert (
            classify_static_suppression("stager_url", "https://1.1.1.1/cdn-cgi/trace")
            == "benign_resolver_ip"
        )
        assert (
            classify_static_suppression("stager_url", "http://[2001:4860:4860::8888]/check")
            == "benign_resolver_ip"
        )

    def test_synthetic_rfc5737_ips_not_suppressed_by_default(self) -> None:
        assert classify_static_suppression("c2_ip", "198.51.100.88") is None
        assert classify_static_suppression("c2_ip", "203.0.113.50") is None
        assert classify_static_suppression("c2_ip", "2001:db8::99") is None

    @pytest.mark.parametrize(
        "domain",
        [
            "github.com",
            "raw.githubusercontent.com",
            "gist.githubusercontent.com",
            "gitlab.com",
            "pastebin.com",
            "cdn.discordapp.com",
            "discord.com",
            "my-bucket.s3.amazonaws.com",
            "d111111abcdef8.cloudfront.net",
            "storage.googleapis.com",
            "drive.google.com",
            "transfer.sh",
            "dropbox.com",
            "evil.workers.dev",
            "something.trycloudflare.com",
            "ghcr.io",
        ],
    )
    def test_shared_hosting_domains_always_suppressed_as_stager_domain(self, domain: str) -> None:
        assert classify_static_suppression("stager_domain", domain) == "shared_hosting_domain"

    def test_shared_hosting_url_allows_non_root_path_but_suppresses_root_url(self) -> None:
        assert (
            classify_static_suppression(
                "stager_url", "https://raw.githubusercontent.com/attacker/repo/main/drop.sh"
            )
            is None
        )
        assert is_shared_hosting_url("https://raw.githubusercontent.com/attacker/repo/main/drop.sh")
        assert (
            classify_static_suppression("stager_url", "https://github.com/")
            == "shared_hosting_root_url"
        )
        assert (
            classify_static_suppression("stager_url", "https://pastebin.com")
            == "shared_hosting_root_url"
        )

    @pytest.mark.parametrize(
        "domain",
        [
            "ifconfig.me",
            "ipinfo.io",
            "api.ipify.org",
            "icanhazip.com",
            "checkip.amazonaws.com",
            "deb.debian.org",
            "archive.ubuntu.com",
            "pypi.org",
            "www.google.com",
            "google.com",
            "www.bing.com",
            "en.wikipedia.org",
        ],
    )
    def test_benign_utility_domains_suppress_both_domain_and_url(self, domain: str) -> None:
        assert classify_static_suppression("stager_domain", domain) == "benign_utility_domain"
        assert (
            classify_static_suppression("stager_url", f"https://{domain}/some/path")
            == "benign_utility_domain"
        )

    def test_longest_suffix_disambiguates_nested_domains(self) -> None:
        # checkip.amazonaws.com (utility) beats amazonaws.com (shared hosting)
        assert (
            classify_static_suppression("stager_url", "https://checkip.amazonaws.com/ip")
            == "benign_utility_domain"
        )
        # drive.google.com (shared hosting) beats google.com (utility)
        assert (
            classify_static_suppression("stager_url", "https://drive.google.com/uc?id=123") is None
        )
        assert is_shared_hosting_url("https://drive.google.com/uc?id=123")
        assert (
            classify_static_suppression("stager_domain", "drive.google.com")
            == "shared_hosting_domain"
        )

    def test_label_boundary_prevents_substring_false_matches(self) -> None:
        assert classify_static_suppression("stager_domain", "evil-github.com") is None
        assert classify_static_suppression("stager_domain", "notgoogle.com") is None
        assert classify_static_suppression("stager_domain", "drop.example.org") is None
        assert not is_shared_hosting_url("https://evil-github.com/stage.sh")

    def test_operator_allowlist_domains_ips_and_cidrs(self) -> None:
        assert (
            classify_static_suppression(
                "stager_domain",
                "sub.corp-partner.example",
                allowlist_domains=["corp-partner.example"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "stager_domain",
                "sub.corp-partner.example",
                allowlist_domains=["*.corp-partner.example"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "stager_domain",
                "corp-partner.example",
                allowlist_domains=[".corp-partner.example"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "stager_url",
                "https://sub.corp-partner.example/path",
                allowlist_domains=["corp-partner.example"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "c2_ip",
                "198.51.100.42",
                allowlist_ips=["198.51.100.0/24"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "c2_ip",
                "198.51.100.42",
                allowlist_ips=["::ffff:198.51.100.0/120"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "c2_ip",
                "2001:db8::42",
                allowlist_ips=["[2001:db8::42]"],
            )
            == "operator_allowlist"
        )
        assert (
            classify_static_suppression(
                "stager_url",
                "http://198.51.100.42:8080/drop.bin",
                allowlist_ips=["198.51.100.42"],
            )
            == "operator_allowlist"
        )

    @pytest.mark.parametrize(
        ("ioc_type", "value", "expected"),
        [
            # Trailing-dot IP-literal URLs
            ("stager_url", "http://1.1.1.1./dns", "benign_resolver_ip"),
            ("c2_ip", "8.8.8.8.", "benign_resolver_ip"),
            # IPv6 zone/scope IDs (raw & percent-encoded)
            ("c2_ip", "2001:4860:4860::8888%eth0", "benign_resolver_ip"),
            ("stager_url", "http://[2001:4860:4860::8888%25eth0]/x", "benign_resolver_ip"),
            # Non-canonical inet_aton IPv4 forms (octal, shorthand, hex, decimal)
            ("stager_url", "http://01.01.01.01/x", "benign_resolver_ip"),
            ("stager_url", "http://1.1/x", "benign_resolver_ip"),
            ("stager_url", "http://0x01010101/x", "benign_resolver_ip"),
            ("stager_url", "http://16843009/x", "benign_resolver_ip"),
            ("stager_url", "http://010.010.010.010/x", "benign_resolver_ip"),
            # Authority backslash parser differential & malformed URLs fail closed
            ("stager_url", "https://github.com\\@evil.example.org/drop.sh", "malformed_url"),
            ("stager_url", "http://[malformed_bracket/x", "malformed_url"),
            # Unicode fullwidth & ideographic-dot normalization (explicit escapes for ASCII source)
            (
                "stager_domain",
                "\uff27\uff29\uff34\uff28\uff35\uff22.\uff23\uff2f\uff2d",
                "shared_hosting_domain",
            ),
            ("stager_url", "https://github.com\u3002/", "shared_hosting_root_url"),
            (
                "stager_url",
                "https://\uff29\uff26\uff23\uff2f\uff2e\uff26\uff29\uff27.\uff2d\uff25/ip",
                "benign_utility_domain",
            ),
        ],
    )
    def test_adversarial_parser_evasion_vectors_suppressed(
        self, ioc_type: str, value: str, expected: str
    ) -> None:
        assert classify_static_suppression(ioc_type, value) == expected

    def test_is_shared_hosting_url_handles_whitespace_and_unicode(self) -> None:
        assert is_shared_hosting_url("  https://raw.githubusercontent.com/org/repo/drop.sh  ")
        assert is_shared_hosting_url(
            "https://\uff27\uff29\uff34\uff28\uff35\uff22.\uff23\uff2f\uff2d/org/repo/drop.sh"
        )


class TestVerificationEvaluation:
    def test_first_party_artifacts_always_verified(self) -> None:
        assert evaluate_ioc_verification("malware_hash", "a" * 64) == (
            VERIFICATION_STATUS_VERIFIED,
            "captured_artifact",
        )
        assert evaluate_ioc_verification("ssh_key", "ssh-ed25519 SHA256:synthetic") == (
            VERIFICATION_STATUS_VERIFIED,
            "captured_artifact",
        )

    def test_stager_url_corroboration_rules(self) -> None:
        url = "http://drop.example.org/stage.sh"
        assert evaluate_ioc_verification("stager_url", url) == (
            VERIFICATION_STATUS_UNVERIFIED,
            "uncorroborated",
        )
        assert evaluate_ioc_verification("stager_url", url, vt_malicious=0) == (
            VERIFICATION_STATUS_UNVERIFIED,
            "uncorroborated",
        )
        assert evaluate_ioc_verification("stager_url", url, vt_malicious=1) == (
            VERIFICATION_STATUS_VERIFIED,
            "vt_malicious",
        )
        assert evaluate_ioc_verification("stager_url", url, gti_verdict="VERDICT_SUSPICIOUS") == (
            VERIFICATION_STATUS_VERIFIED,
            "gti_verdict",
        )
        assert evaluate_ioc_verification("stager_url", url, captured_artifact=True) == (
            VERIFICATION_STATUS_VERIFIED,
            "captured_artifact",
        )

    def test_shared_hosting_url_requires_corroboration_or_is_suppressed(self) -> None:
        gh_url = "https://raw.githubusercontent.com/attacker/repo/main/drop.sh"
        assert evaluate_ioc_verification("stager_url", gh_url, vt_malicious=0) == (
            VERIFICATION_STATUS_SUPPRESSED,
            "shared_hosting_unverified_url",
        )
        assert evaluate_ioc_verification("stager_url", gh_url, vt_malicious=1) == (
            VERIFICATION_STATUS_VERIFIED,
            "vt_malicious",
        )
        assert evaluate_ioc_verification("stager_url", gh_url, captured_artifact=True) == (
            VERIFICATION_STATUS_VERIFIED,
            "captured_artifact",
        )

    def test_stager_domain_requires_vt_3_or_gti(self) -> None:
        dom = "drop.example.org"
        # VT 1-2 is single-engine noise under VT_IP_RISK_BUCKETS
        assert evaluate_ioc_verification("stager_domain", dom, vt_malicious=2) == (
            VERIFICATION_STATUS_UNVERIFIED,
            "uncorroborated",
        )
        assert evaluate_ioc_verification("stager_domain", dom, vt_malicious=3) == (
            VERIFICATION_STATUS_VERIFIED,
            "vt_malicious",
        )
        assert evaluate_ioc_verification("stager_domain", dom, gti_verdict="VERDICT_MALICIOUS") == (
            VERIFICATION_STATUS_VERIFIED,
            "gti_verdict",
        )
        # Even if VT flags github.com, shared_hosting_domain always suppresses
        assert evaluate_ioc_verification(
            "stager_domain", "raw.githubusercontent.com", vt_malicious=99
        ) == (VERIFICATION_STATUS_SUPPRESSED, "shared_hosting_domain")

    def test_c2_ip_corroboration_and_greynoise_riot_override(self) -> None:
        ip = "198.51.100.88"
        assert evaluate_ioc_verification("c2_ip", ip, vt_malicious=2) == (
            VERIFICATION_STATUS_UNVERIFIED,
            "uncorroborated",
        )
        assert evaluate_ioc_verification("c2_ip", ip, vt_malicious=3) == (
            VERIFICATION_STATUS_VERIFIED,
            "vt_malicious",
        )
        assert evaluate_ioc_verification("c2_ip", ip, greynoise_class="malicious") == (
            VERIFICATION_STATUS_VERIFIED,
            "greynoise_malicious",
        )
        assert evaluate_ioc_verification("c2_ip", ip, abuseipdb_confidence=49) == (
            VERIFICATION_STATUS_UNVERIFIED,
            "uncorroborated",
        )
        assert evaluate_ioc_verification("c2_ip", ip, abuseipdb_confidence=50) == (
            VERIFICATION_STATUS_VERIFIED,
            "abuseipdb_malicious",
        )
        assert evaluate_ioc_verification("c2_ip", ip, captured_artifact=True) == (
            VERIFICATION_STATUS_VERIFIED,
            "captured_artifact",
        )
        # GreyNoise RIOT / benign always overrides even hot VT/AbuseIPDB/capture signals
        assert evaluate_ioc_verification(
            "c2_ip",
            ip,
            vt_malicious=15,
            abuseipdb_confidence=100,
            captured_artifact=True,
            greynoise_riot=True,
        ) == (VERIFICATION_STATUS_SUPPRESSED, "greynoise_riot")
        assert evaluate_ioc_verification(
            "c2_ip",
            ip,
            vt_malicious=15,
            greynoise_class="benign",
        ) == (VERIFICATION_STATUS_SUPPRESSED, "greynoise_benign")


class TestShouldExportIocToStix:
    def test_default_policy_omits_unverified_and_suppressed(self) -> None:
        cfg = StixExportConfig()
        ok, status, reason = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_url",
                "ioc_value": "http://unknown.example.org/x.sh",
                "verification_status": VERIFICATION_STATUS_UNVERIFIED,
                "verification_reason": "uncorroborated",
            },
            cfg,
        )
        assert not ok
        assert status == VERIFICATION_STATUS_UNVERIFIED
        assert reason == "uncorroborated"

    def test_opt_in_exports_unverified_non_shared_but_never_shared_or_suppressed(self) -> None:
        cfg = StixExportConfig(include_unverified_outbound=True)
        ok_unknown, status_unknown, _ = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_url",
                "ioc_value": "http://unknown.example.org/x.sh",
                "verification_status": VERIFICATION_STATUS_UNVERIFIED,
                "verification_reason": "uncorroborated",
            },
            cfg,
        )
        assert ok_unknown
        assert status_unknown == VERIFICATION_STATUS_UNVERIFIED

        # Unverified GitHub URL is STILL blocked even with include_unverified_outbound=True
        ok_gh, status_gh, reason_gh = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_url",
                "ioc_value": "https://raw.githubusercontent.com/org/repo/main/README.md",
                "verification_status": VERIFICATION_STATUS_UNVERIFIED,
                "verification_reason": "uncorroborated",
            },
            cfg,
        )
        assert not ok_gh
        assert status_gh == VERIFICATION_STATUS_SUPPRESSED
        assert reason_gh == "shared_hosting_unverified_url"

        # Operator allowlist overrides even pre-verified rows at STIX export time
        cfg_allow = StixExportConfig(
            include_unverified_outbound=True, allowlist_domains=["partner.example.org"]
        )
        ok_allow, status_allow, reason_allow = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_domain",
                "ioc_value": "partner.example.org",
                "verification_status": VERIFICATION_STATUS_VERIFIED,
                "verification_reason": "vt_malicious",
            },
            cfg_allow,
        )
        assert not ok_allow
        assert status_allow == VERIFICATION_STATUS_SUPPRESSED
        assert reason_allow == "operator_allowlist"

    def test_legacy_row_without_verification_columns_recomputes_safely(self) -> None:
        cfg = StixExportConfig()
        # Legacy verified VT URL -> allowed
        ok_v, status_v, reason_v = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_url",
                "ioc_value": "http://drop.example.org/a.sh",
                "vt_malicious": 3,
                "gti_verdict": None,
            },
            cfg,
        )
        assert ok_v
        assert status_v == VERIFICATION_STATUS_VERIFIED
        assert reason_v == "vt_malicious"

        # Legacy unverified URL -> blocked
        ok_u, status_u, _ = should_export_ioc_to_stix(
            {
                "ioc_type": "stager_url",
                "ioc_value": "http://bank.example.org/x",
                "vt_malicious": None,
                "gti_verdict": None,
            },
            cfg,
        )
        assert not ok_u
        assert status_u == VERIFICATION_STATUS_UNVERIFIED

        # Legacy DNS resolver IP -> suppressed
        ok_r, status_r, reason_r = should_export_ioc_to_stix(
            {
                "ioc_type": "c2_ip",
                "ioc_value": "1.1.1.1",
                "vt_malicious": 10,
                "gti_verdict": None,
            },
            cfg,
        )
        assert not ok_r
        assert status_r == VERIFICATION_STATUS_SUPPRESSED
        assert reason_r == "benign_resolver_ip"
