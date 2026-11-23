"""Unit tests for self-owned container build-time offline/security patches."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
COWRIE_PATCH = REPO_ROOT / "containers" / "cowrie" / "patch_offline.py"
DIONAEA_FTP_PATCH = REPO_ROOT / "containers" / "dionaea" / "patch_ftp.py"
DIONAEA_CFG = REPO_ROOT / "containers" / "dionaea" / "dionaea.cfg"


def _load_module(name: str, path: Path) -> ModuleType:
    prev = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = prev


class TestDionaeaContainerHardening:
    def test_dionaea_cfg_is_ascii_and_disables_curl_and_bistreams(self) -> None:
        raw = DIONAEA_CFG.read_bytes()
        text = raw.decode("ascii")
        assert "\nmodules=python,emu\n" in text
        assert "\nprocessors=filter_emu\n" in text
        assert "curl" not in next(
            line.split("=", 1)[1].strip()
            for line in text.splitlines()
            if line.startswith("modules=")
        ).split(",")

    def test_patch_ftp_is_ascii_and_disables_active_port_mode(self, tmp_path: Path) -> None:
        # Must stay strictly 7-bit ASCII for Dionaea's embedded Python 3.6
        DIONAEA_FTP_PATCH.read_bytes().decode("ascii")
        mod = _load_module("dionaea_patch_ftp", DIONAEA_FTP_PATCH)

        sample_ftp = tmp_path / "ftp.py"
        sample_ftp.write_text(
            "class FTPd:\n"
            "    def ftp_FEAT(self):\n"
            "        self.send('211-Features:\\r\\n' +\n"
            "                  ' PASV\\r\\n' +\n"
            "                  ' PORT\\r\\n' +\n"
            "                  '211 End\\r\\n')\n"
            "        return None\n"
            "\n"
            "    def ftp_PORT(self, address):\n"
            "        if self.dtf:\n"
            "            self.dtf.close()\n"
            "            self.dtf = None\n"
            "        if self.dtp:\n"
            "            self.dtp.close()\n"
            "            self.dtp = None\n"
            "        addr = list(map(int, address.split(',')))\n"
            "        ip = '%d.%d.%d.%d' % tuple(addr[:4])\n"
            "        port = addr[4] << 8 | addr[5]\n"
            '        logger.debug("PORT cmd for port %i" % port)\n'
            '        if self.remote.host != ip and "::ffff:" + self.remote.host != ip:\n'
            '            logger.warn("Potential FTP Bounce Scan detected")\n'
            "            return None\n"
            "        self.dtp = FTPDataConnect(ip, port, self)\n"
            "        return None\n",
            encoding="ascii",
        )

        mod.patch_ftp_file(str(sample_ftp))
        patched = sample_ftp.read_text(encoding="ascii")
        assert "FTPDataConnect(" not in patched
        assert "' PORT\\r\\n'" not in patched
        assert 'self.reply("cmd_not_implmntd", command="PORT")' in patched
        compile(patched, str(sample_ftp), "exec")

    def test_patch_ftp_fails_loudly_on_anchor_drift(self, tmp_path: Path) -> None:
        mod = _load_module("dionaea_patch_ftp_drift", DIONAEA_FTP_PATCH)
        bad = tmp_path / "ftp.py"
        bad.write_text("class FTPd:\n    pass\n", encoding="ascii")
        with pytest.raises(RuntimeError):
            mod.patch_ftp_file(str(bad))


class TestCowrieOfflinePatch:
    def test_patch_offline_short_circuits_network_and_tftp_dns(self, tmp_path: Path) -> None:
        mod = _load_module("cowrie_patch_offline", COWRIE_PATCH)

        net_py = tmp_path / "network.py"
        net_py.write_text(
            "@inlineCallbacks\n"
            "def resolve_cname(\n"
            "    address: str, visited: set[str]\n"
            ") -> Generator[Deferred, None, str | None]:\n"
            "    _log.debug('x')\n"
            "    return None\n"
            "\n"
            "@inlineCallbacks\n"
            "def resolve_allowed(address: str) -> Generator[Deferred, None, str | None]:\n"
            '    """\n'
            "    Resolve an IP or DNS name once, validate the resolved IP against the\n"
            "    blocklist, and return that exact IP (or None if unresolvable or blocked).\n"
            '    """\n'
            "    # First, check if it's already a valid IP address (either IPv4 or IPv6)\n"
            "    ip = is_ip_address(address)\n"
            "    return str(ip)\n",
            encoding="utf-8",
        )

        tftp_py = tmp_path / "tftp.py"
        tftp_py.write_text(
            "class Command_tftp:\n"
            "    def start(self):\n"
            "        if is_ip_address(self.hostname) is not None:\n"
            "            self.host_ip = self.hostname\n"
            "        else:\n"
            "            try:\n"
            "                self.host_ip = yield reactor.resolve(self.hostname)\n"
            "            except Exception:\n"
            "                self._log.info(\n"
            '                    "TFTP: could not resolve host {host}", host=self.hostname\n'
            "                )\n"
            '                self.write(f"tftp: {self.hostname}: Name or service not known\\n")\n'
            "                self.exit(1)\n"
            "                return\n"
            "\n"
            "        # Validate the address that will actually be contacted. Resolving the\n"
            "        # hostname a second time here would let a DNS answer that changes\n"
            "        # between lookups (rebinding) point the transfer at a private or\n"
            "        # metadata address after a public one passed the check.\n"
            "        allowed = yield communication_allowed(self.host_ip)\n"
            "        if not allowed:\n"
            "            self._log.info(\n"
            '                "TFTP: attempt to access blocked network address {ip}",\n'
            "                ip=self.host_ip,\n"
            "            )\n"
            "            self.exit(1)\n"
            "            return\n",
            encoding="utf-8",
        )

        mod.patch_network_file(str(net_py))
        mod.patch_tftp_file(str(tftp_py))

        net_patched = net_py.read_text(encoding="utf-8")
        tftp_patched = tftp_py.read_text(encoding="utf-8")

        assert "return None" in net_patched
        assert "reactor.resolve(" not in tftp_patched
        assert "Name or service not known" in tftp_patched
        compile(net_patched, str(net_py), "exec")
        compile(tftp_patched, str(tftp_py), "exec")

    def test_patch_offline_fails_loudly_on_anchor_drift(self, tmp_path: Path) -> None:
        mod = _load_module("cowrie_patch_offline_drift", COWRIE_PATCH)
        bad = tmp_path / "network.py"
        bad.write_text("def other(): pass\n", encoding="utf-8")
        with pytest.raises(RuntimeError):
            mod.patch_network_file(str(bad))
