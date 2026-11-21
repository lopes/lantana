# Lantana rich JSON ihandler for Dionaea.
# Strictly 7-bit ASCII (Dionaea embeds Python 3.6 + PyYAML).
#
# Extends upstream log_json with:
#   - UTC ISO-8601 timestamps ending in "Z"
#   - Structured HTTP request fields (method, URI, user-agent, host,
#     content-type, bounded body preview for IoT RCE / LLM / MCP POST probes)
#   - MSSQL and MySQL command text (sql_command)
#   - Per-session attributed binary captures (eventid=dionaea.binary.captured,
#     SHA-256, MD5, src_ip, dst_port, download_url, binary_file_name)

from datetime import datetime
import hashlib
import logging
import os

from dionaea import IHandlerLoader
from dionaea.exception import LoaderError
from dionaea.log_json import LogJsonHandler

logger = logging.getLogger("lantana_json")
logger.setLevel(logging.INFO)

MAX_HTTP_BODY_PREVIEW = 512
MAX_SQL_COMMAND_LEN = 1024
MAX_TEXT_FIELD_LEN = 1024
HASH_CHUNK_BYTES = 65536

MYSQL_COMMANDS = {
    0: "COM_SLEEP",
    1: "COM_QUIT",
    2: "COM_INIT_DB",
    3: "COM_QUERY",
    4: "COM_FIELD_LIST",
    5: "COM_CREATE_DB",
    6: "COM_DROP_DB",
    7: "COM_REFRESH",
    8: "COM_SHUTDOWN",
    9: "COM_STATISTICS",
    10: "COM_PROCESS_INFO",
    11: "COM_CONNECT",
    12: "COM_PROCESS_KILL",
    13: "COM_DEBUG",
    14: "COM_PING",
    22: "COM_STMT_PREPARE",
    23: "COM_STMT_EXECUTE",
}


def _utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class LantanaJsonHandlerLoader(IHandlerLoader):
    name = "lantana_json"

    @classmethod
    def start(cls, config=None):
        try:
            return LantanaJsonHandler("*", config=config or {})
        except LoaderError as exc:
            logger.error(exc.msg, *exc.args)
            return None


class LantanaJsonHandler(LogJsonHandler):
    def _clean_text(self, value, max_len=MAX_TEXT_FIELD_LEN):
        if value is None:
            return ""
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = str(value)
        text = text.replace("\x00", "")
        if len(text) > max_len:
            return text[:max_len]
        return text

    def _submit_record(self, record):
        payload = self._flatten_data(record) if self.flat_data else record
        for handler in self.handlers:
            try:
                handler.submit(payload)
            except Exception:
                logger.warning("Failed to submit lantana_json record", exc_info=True)

    def _serialize_connection(self, icd, connection_type):
        super(LantanaJsonHandler, self)._serialize_connection(icd, connection_type)
        data = self.attacks.get(icd.con)
        if data is not None:
            data["timestamp"] = _utc_now_iso()

    def _base_connection_record(self, con, connection_type="accept"):
        if con is None:
            return {
                "connection": {
                    "protocol": "unknown",
                    "transport": "tcp",
                    "type": connection_type,
                },
                "dst_ip": "",
                "dst_port": 0,
                "src_hostname": "",
                "src_ip": "",
                "src_port": 0,
                "timestamp": _utc_now_iso(),
            }
        return {
            "connection": {
                "protocol": getattr(con, "protocol", "unknown"),
                "transport": getattr(con, "transport", "tcp"),
                "type": connection_type,
            },
            "dst_ip": con.local.host,
            "dst_port": con.local.port,
            "src_hostname": self._clean_text(con.remote.hostname, 255),
            "src_ip": con.remote.host,
            "src_port": con.remote.port,
            "timestamp": _utc_now_iso(),
        }

    def handle_incident_dionaea_modules_python_http_request(self, icd):
        con = getattr(icd, "con", None)
        http_fields = {
            "http_method": self._clean_text(getattr(icd, "method", ""), 32),
            "http_uri": self._clean_text(getattr(icd, "uri", ""), MAX_TEXT_FIELD_LEN),
            "http_user_agent": self._clean_text(getattr(icd, "user_agent", ""), 512),
            "http_host": self._clean_text(getattr(icd, "host", ""), 255),
            "http_content_type": self._clean_text(getattr(icd, "content_type", ""), 255),
            "http_body_preview": self._clean_text(
                getattr(icd, "body_preview", ""), MAX_HTTP_BODY_PREVIEW
            ),
        }
        data = self.attacks.get(con) if con is not None else None
        if data is not None and "http_method" not in data:
            data.update(http_fields)
            return
        # Keep-alive second request or untracked connection: emit standalone record
        record = self._base_connection_record(con, "accept")
        record.update(http_fields)
        self._submit_record(record)

    def _append_sql_command(self, con, cmd_text):
        cleaned = self._clean_text(cmd_text, MAX_SQL_COMMAND_LEN).strip()
        if not cleaned or con is None:
            return
        data = self.attacks.get(con)
        if data is None:
            return
        existing = data.get("sql_command")
        if existing:
            combined = "%s; %s" % (existing, cleaned)
            data["sql_command"] = combined[:MAX_SQL_COMMAND_LEN]
        else:
            data["sql_command"] = cleaned

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        self._append_sql_command(getattr(icd, "con", None), getattr(icd, "cmd", ""))

    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        con = getattr(icd, "con", None)
        cmd_id = getattr(icd, "command", None)
        args = getattr(icd, "args", None) or []
        formatted_args = " ".join(
            self._clean_text(arg, MAX_SQL_COMMAND_LEN).strip() for arg in args if arg
        ).strip()
        if cmd_id == 3 and formatted_args:
            self._append_sql_command(con, formatted_args)
            return
        cmd_name = MYSQL_COMMANDS.get(cmd_id, "MYSQL_CMD_%s" % cmd_id)
        text = ("%s %s" % (cmd_name, formatted_args)).strip()
        self._append_sql_command(con, text)

    def _handle_binary_capture(self, icd):
        file_path = getattr(icd, "file", None)
        if not file_path or not os.path.isfile(file_path):
            return
        try:
            sha256_hex = _sha256_file(file_path)
        except OSError as exc:
            logger.warning("Failed hashing captured binary %s: %s", file_path, exc)
            return

        con = getattr(icd, "con", None)
        record = self._base_connection_record(con, "accept")
        record["eventid"] = "dionaea.binary.captured"
        record["shasum"] = sha256_hex
        record["md5"] = self._clean_text(getattr(icd, "md5hash", ""), 64)
        record["binary_file_name"] = os.path.basename(file_path)
        download_url = self._clean_text(getattr(icd, "url", ""), MAX_TEXT_FIELD_LEN).strip()
        if download_url:
            record["download_url"] = download_url
        self._submit_record(record)

    def handle_incident_dionaea_download_complete_unique(self, icd):
        self._handle_binary_capture(icd)

    def handle_incident_dionaea_download_complete_again(self, icd):
        self._handle_binary_capture(icd)
