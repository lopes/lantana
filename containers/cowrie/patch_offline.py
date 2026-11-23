"""Build-time patch to make Lantana's Cowrie image strictly non-egressing.

Short-circuits outbound DNS/TCP/UDP lookups in Cowrie's network gatekeeper
(``cowrie/core/network.py``) and TFTP command (``cowrie/commands/tftp.py``) so
attacker-issued ``wget``, ``curl``, ``ftpget``, ``nc``, and ``tftp`` commands
never leave the container while still logging every URL/host and returning
realistic CLI failure messages.
"""

from __future__ import annotations

import sys

NETWORK_PY = "/cowrie/cowrie-git/src/cowrie/core/network.py"
TFTP_PY = "/cowrie/cowrie-git/src/cowrie/commands/tftp.py"


def replace_once(src: str, old: str, new: str, label: str, path: str) -> str:
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"Expected exactly 1 match for {label} in {path}, found {count}")
    return src.replace(old, new, 1)


def patch_network_file(path: str = NETWORK_PY) -> None:
    with open(path, encoding="utf-8") as fh:
        src = fh.read()

    src = replace_once(
        src,
        (
            "@inlineCallbacks\n"
            "def resolve_cname(\n"
            "    address: str, visited: set[str]\n"
            ") -> Generator[Deferred, None, str | None]:\n"
        ),
        (
            "@inlineCallbacks\n"
            "def resolve_cname(\n"
            "    address: str, visited: set[str]\n"
            ") -> Generator[Deferred, None, str | None]:\n"
            "    _log.debug(\n"
            '        "Lantana offline mode: blocked DNS lookup for {address!r}",\n'
            "        address=address,\n"
            "    )\n"
            "    if False:\n"
            "        yield  # preserve generator semantics for Twisted @inlineCallbacks\n"
            "    return None\n"
        ),
        "resolve_cname",
        path,
    )

    src = replace_once(
        src,
        (
            "@inlineCallbacks\n"
            "def resolve_allowed(address: str) -> Generator[Deferred, None, str | None]:\n"
        ),
        (
            "@inlineCallbacks\n"
            "def resolve_allowed(address: str) -> Generator[Deferred, None, str | None]:\n"
            "    _log.info(\n"
            '        "Lantana offline mode: blocked outbound target {address!r}",\n'
            "        address=address,\n"
            "    )\n"
            "    if False:\n"
            "        yield  # preserve generator semantics for Twisted @inlineCallbacks\n"
            "    return None\n"
        ),
        "resolve_allowed",
        path,
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)


def patch_tftp_file(path: str = TFTP_PY) -> None:
    with open(path, encoding="utf-8") as fh:
        src = fh.read()

    old_block = (
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
        "            return\n"
    )
    new_block = (
        "        # Lantana offline mode: never perform outbound DNS resolution or UDP I/O.\n"
        "        allowed = yield communication_allowed(self.hostname)\n"
        "        if not allowed:\n"
        "            self._log.info(\n"
        '                "TFTP: blocked outbound target {host}",\n'
        "                host=self.hostname,\n"
        "            )\n"
        '            self.write(f"tftp: {self.hostname}: Name or service not known\\n")\n'
        "            self.exit(1)\n"
        "            return\n"
        "        self.host_ip = self.hostname\n"
    )
    src = replace_once(src, old_block, new_block, "tftp_resolve", path)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)


def main() -> None:
    patch_network_file()
    patch_tftp_file()
    print(f"Patched {NETWORK_PY} and {TFTP_PY} for offline operation.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write(f"patch_offline.py failed: {exc}\n")
        sys.exit(1)
