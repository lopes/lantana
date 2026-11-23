# Build-time patch for Dionaea's ftp.py to disable active-mode FTP PORT
# outbound connections (eliminating FTP bounce / unsolicited egress) while
# keeping passive-mode PASV uploads fully functional.
# Strictly 7-bit ASCII (executed under Python 3.6 during image build).

import sys

FTP_PY = "/opt/dionaea/lib/dionaea/python/dionaea/ftp.py"


def replace_once(src, old, new, label, path):
    count = src.count(old)
    if count != 1:
        raise RuntimeError(
            "Expected exactly 1 match for %s in %s, found %d" % (label, path, count)
        )
    return src.replace(old, new, 1)


def patch_ftp_file(path=FTP_PY):
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()

    old_feat = (
        "    def ftp_FEAT(self):\n"
        "        self.send('211-Features:\\r\\n' +\n"
        "                  ' PASV\\r\\n' +\n"
        "                  ' PORT\\r\\n' +\n"
        "                  '211 End\\r\\n')\n"
        "        return None\n"
    )
    new_feat = (
        "    def ftp_FEAT(self):\n"
        "        self.send('211-Features:\\r\\n' +\n"
        "                  ' PASV\\r\\n' +\n"
        "                  '211 End\\r\\n')\n"
        "        return None\n"
    )
    src = replace_once(src, old_feat, new_feat, "ftp_FEAT", path)

    old_port = (
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
        "        return None\n"
    )
    new_port = (
        "    def ftp_PORT(self, address):\n"
        "        if self.dtf:\n"
        "            self.dtf.close()\n"
        "            self.dtf = None\n"
        "        if self.dtp:\n"
        "            self.dtp.close()\n"
        "            self.dtp = None\n"
        '        logger.info("Lantana offline mode: rejected active FTP PORT command")\n'
        '        self.reply("cmd_not_implmntd", command="PORT")\n'
        "        return None\n"
    )
    src = replace_once(src, old_port, new_port, "ftp_PORT", path)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)


def main():
    patch_ftp_file()
    print("Patched %s successfully." % FTP_PY)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write("patch_ftp.py failed: %s\n" % exc)
        sys.exit(1)
