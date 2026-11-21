# Build-time patch for Dionaea's http.py to emit structured HTTP request
# incidents (method, raw URI with query, user-agent, host, content-type,
# bounded POST/PUT body preview) without enabling bistreams or PCAPs.
# Strictly 7-bit ASCII (executed under Python 3.6 during image build).

import sys

HTTP_PY = "/opt/dionaea/lib/dionaea/python/dionaea/http.py"


def replace_once(src, old, new, label):
    count = src.count(old)
    if count != 1:
        raise RuntimeError(
            "Expected exactly 1 match for %s in %s, found %d" % (label, HTTP_PY, count)
        )
    return src.replace(old, new, 1)


def main():
    with open(HTTP_PY, "r", encoding="utf-8") as fh:
        src = fh.read()

    # 1. Preserve raw URI (including query string) and tolerate non-UTF-8 bytes.
    src = replace_once(
        src,
        "        path_parsed = urllib.parse.urlsplit(reqparts[1].decode('utf-8'))\n",
        (
            "        self.raw_uri = reqparts[1].decode('utf-8', errors='replace')\n"
            "        path_parsed = urllib.parse.urlsplit(self.raw_uri)\n"
        ),
        "httpreq.raw_uri",
    )

    # 2. Add _emit_http_incident helper right before handle_io_in.
    helper = (
        "    def _emit_http_incident(self, body_bytes=b''):\n"
        "        if self.header is None:\n"
        "            return\n"
        "        try:\n"
        "            icd = incident('dionaea.modules.python.http.request')\n"
        "            icd.con = self\n"
        "            icd.method = self.header.type.decode('utf-8', errors='replace')\n"
        "            icd.uri = getattr(self.header, 'raw_uri', None) or self.header.path\n"
        "            headers = self.header.headers\n"
        "            icd.user_agent = headers.get(b'user-agent', b'').decode('utf-8', errors='replace')\n"
        "            icd.host = headers.get(b'host', b'').decode('utf-8', errors='replace')\n"
        "            icd.content_type = headers.get(b'content-type', b'').decode('utf-8', errors='replace')\n"
        "            if isinstance(body_bytes, bytes):\n"
        "                preview = body_bytes[:512].decode('utf-8', errors='replace')\n"
        "            else:\n"
        "                preview = str(body_bytes)[:512]\n"
        "            icd.body_preview = preview.replace('\\x00', '')\n"
        "            icd.report()\n"
        "        except Exception:\n"
        "            logger.warning('Failed to emit http.request incident', exc_info=True)\n"
        "\n"
        "    def handle_io_in(self, data):\n"
    )
    src = replace_once(
        src,
        "    def handle_io_in(self, data):\n",
        helper,
        "emit_http_incident_helper",
    )

    # 3. Emit incident for GET, HEAD, OPTIONS, POST-without-ct/bad-cl, SOAP, unknown.
    src = replace_once(
        src,
        "            if self.header.type == b'GET':\n                self.handle_GET()\n",
        "            if self.header.type == b'GET':\n                self._emit_http_incident()\n                self.handle_GET()\n",
        "http_GET",
    )
    src = replace_once(
        src,
        "            elif self.header.type == b'HEAD':\n                self.handle_HEAD()\n",
        "            elif self.header.type == b'HEAD':\n                self._emit_http_incident()\n                self.handle_HEAD()\n",
        "http_HEAD",
    )
    src = replace_once(
        src,
        (
            "            elif self.header.type == b'POST':\n"
            "                if b'content-type' not in self.header.headers and b'content-type' not in self.header.headers:\n"
            "                    self.handle_POST()\n"
            "                    return len(data)\n"
            "\n"
            "                if self.soap_enabled and b\"soapaction\" in self.header.headers:\n"
            "                    return self.handle_POST_SOAP(data)\n"
            "\n"
            "                try:\n"
            "                    self.content_length = int(self.header.headers[b'content-length'].decode(\"utf-8\"))\n"
            "                    self.content_type = self.header.headers[b'content-type'].decode(\"utf-8\")\n"
            "                except Exception:\n"
            "                    # ignore decode() errors\n"
            "                    logger.warning(\"Ignoring decode errors\", exc_info=True)\n"
            "                    self.handle_POST()\n"
            "                    return len(data)\n"
        ),
        (
            "            elif self.header.type == b'POST':\n"
            "                if b'content-type' not in self.header.headers:\n"
            "                    self._emit_http_incident(data[:512])\n"
            "                    self.handle_POST()\n"
            "                    return len(data)\n"
            "\n"
            "                if self.soap_enabled and b\"soapaction\" in self.header.headers:\n"
            "                    self._emit_http_incident(data[:512])\n"
            "                    return self.handle_POST_SOAP(data)\n"
            "\n"
            "                try:\n"
            "                    self.content_length = int(self.header.headers[b'content-length'].decode(\"utf-8\"))\n"
            "                    self.content_type = self.header.headers[b'content-type'].decode(\"utf-8\")\n"
            "                except Exception:\n"
            "                    logger.warning(\"Ignoring decode errors\", exc_info=True)\n"
            "                    self._emit_http_incident(data[:512])\n"
            "                    self.handle_POST()\n"
            "                    return len(data)\n"
        ),
        "http_POST_fallback",
    )
    src = replace_once(
        src,
        "            elif self.header.type == b'OPTIONS':\n                self.handle_OPTIONS()\n",
        "            elif self.header.type == b'OPTIONS':\n                self._emit_http_incident()\n                self.handle_OPTIONS()\n",
        "http_OPTIONS",
    )
    src = replace_once(
        src,
        "            # method not found\n            self.handle_unknown()\n",
        "            # method not found\n            self._emit_http_incident(data[:512])\n            self.handle_unknown()\n",
        "http_unknown",
    )

    # 4. In handle_POST, emit incident with bounded body preview from fp_tmp,
    #    handle non-form bodies (e.g. application/json) without raising or
    #    leaking http-*.tmp files, and carry upload URI on multipart files.
    old_handle_post_block = (
        "        if self.fp_tmp is not None:\n"
        "            self.fp_tmp.seek(0)\n"
        "            # at least this information are needed for\n"
        "            # cgi.FieldStorage() to parse the content\n"
        "            tmp_environ = {\n"
        "                'REQUEST_METHOD': 'POST',\n"
        "                'CONTENT_LENGTH': self.content_length,\n"
        "                'CONTENT_TYPE': self.content_type\n"
        "            }\n"
        "            if sys.version_info[1] >= 8:\n"
        "                self.request_form = cgi.FieldStorage(\n"
        "                    fp=self.fp_tmp,\n"
        "                    environ=tmp_environ,\n"
        "                    max_num_fields=self.get_max_num_fields\n"
        "                )\n"
        "            else:\n"
        "                logger.warning(\"max_num_fields is only supported with Python >= 3.8\")\n"
        "                self.request_form = cgi.FieldStorage(\n"
        "                    fp=self.fp_tmp,\n"
        "                    environ=tmp_environ\n"
        "                )\n"
        "            for field_name in self.request_form.keys():\n"
        "                # dump only files\n"
        "                if self.request_form[field_name].filename is None:\n"
        "                    continue\n"
        "\n"
        "                fp_post = self.request_form[field_name].file\n"
        "\n"
        "                data = fp_post.read(4096)\n"
        "\n"
        "                # don't handle empty files\n"
        "                if len(data) == 0:\n"
        "                    continue\n"
        "\n"
        "                fp_tmp = tempfile.NamedTemporaryFile(\n"
        "                    delete=False,\n"
        "                    dir=self.download_dir,\n"
        "                    prefix='http-',\n"
        "                    suffix=self.download_suffix\n"
        "                )\n"
        "                while data != b'':\n"
        "                    fp_tmp.write(data)\n"
        "                    data = fp_post.read(4096)\n"
        "\n"
        "                icd = incident(\"dionaea.download.complete\")\n"
        "                icd.path = fp_tmp.name\n"
        "                icd.con = self\n"
        "                # We need the url for logging\n"
        "                icd.url = \"\"\n"
        "                fp_tmp.close()\n"
        "                icd.report()\n"
        "                os.unlink(fp_tmp.name)\n"
        "\n"
        "            os.unlink(self.fp_tmp.name)\n"
    )
    new_handle_post_block = (
        "        if self.fp_tmp is not None:\n"
        "            tmp_path = self.fp_tmp.name\n"
        "            try:\n"
        "                self.fp_tmp.seek(0)\n"
        "                self._emit_http_incident(self.fp_tmp.read(512))\n"
        "                self.fp_tmp.seek(0)\n"
        "                ct_lower = (self.content_type or '').lower()\n"
        "                if 'multipart/form-data' in ct_lower or 'application/x-www-form-urlencoded' in ct_lower:\n"
        "                    tmp_environ = {\n"
        "                        'REQUEST_METHOD': 'POST',\n"
        "                        'CONTENT_LENGTH': str(self.content_length),\n"
        "                        'CONTENT_TYPE': self.content_type\n"
        "                    }\n"
        "                    if sys.version_info[1] >= 8:\n"
        "                        self.request_form = cgi.FieldStorage(\n"
        "                            fp=self.fp_tmp,\n"
        "                            environ=tmp_environ,\n"
        "                            max_num_fields=self.get_max_num_fields\n"
        "                        )\n"
        "                    else:\n"
        "                        self.request_form = cgi.FieldStorage(\n"
        "                            fp=self.fp_tmp,\n"
        "                            environ=tmp_environ\n"
        "                        )\n"
        "                    for field_name in self.request_form.keys():\n"
        "                        if self.request_form[field_name].filename is None:\n"
        "                            continue\n"
        "                        fp_post = self.request_form[field_name].file\n"
        "                        data = fp_post.read(4096)\n"
        "                        if len(data) == 0:\n"
        "                            continue\n"
        "                        fp_tmp = tempfile.NamedTemporaryFile(\n"
        "                            delete=False,\n"
        "                            dir=self.download_dir,\n"
        "                            prefix='http-',\n"
        "                            suffix=self.download_suffix\n"
        "                        )\n"
        "                        while data != b'':\n"
        "                            fp_tmp.write(data)\n"
        "                            data = fp_post.read(4096)\n"
        "                        icd = incident('dionaea.download.complete')\n"
        "                        icd.path = fp_tmp.name\n"
        "                        icd.con = self\n"
        "                        icd.url = (getattr(self.header, 'raw_uri', '') if self.header else '')\n"
        "                        fp_tmp.close()\n"
        "                        icd.report()\n"
        "                        os.unlink(fp_tmp.name)\n"
        "            except Exception:\n"
        "                logger.warning('Failed parsing HTTP POST body', exc_info=True)\n"
        "            finally:\n"
        "                try:\n"
        "                    self.fp_tmp.close()\n"
        "                except Exception:\n"
        "                    pass\n"
        "                self.fp_tmp = None\n"
        "                if os.path.exists(tmp_path):\n"
        "                    os.unlink(tmp_path)\n"
    )
    src = replace_once(src, old_handle_post_block, new_handle_post_block, "http_POST_block")

    with open(HTTP_PY, "w", encoding="utf-8") as fh:
        fh.write(src)
    print("Patched %s successfully." % HTTP_PY)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write("patch_http.py failed: %s\n" % exc)
        sys.exit(1)
