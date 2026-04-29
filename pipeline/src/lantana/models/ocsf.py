"""OCSF (Open Cybersecurity Schema Framework) Pydantic models.

These models define the schema contract for silver-layer events.
Normalization functions in normalize.py produce DataFrames conforming
to these models. OCSF v1.3.0 class UIDs and category UIDs are used.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs runtime access

from pydantic import BaseModel

OCSF_VERSION: str = "1.3.0"
PRODUCT_NAME: str = "Lantana"

# OCSF Category UIDs
CATEGORY_SYSTEM: int = 1
CATEGORY_FINDINGS: int = 2
CATEGORY_IAM: int = 3
CATEGORY_NETWORK: int = 4

# OCSF Class UIDs
CLASS_FILE_ACTIVITY: int = 1001
CLASS_PROCESS_ACTIVITY: int = 1007
CLASS_DETECTION_FINDING: int = 2004
CLASS_AUTHENTICATION: int = 3002
CLASS_NETWORK_ACTIVITY: int = 4001

# OCSF Severity IDs
SEVERITY_UNKNOWN: int = 0
SEVERITY_INFORMATIONAL: int = 1
SEVERITY_LOW: int = 2
SEVERITY_MEDIUM: int = 3
SEVERITY_HIGH: int = 4
SEVERITY_CRITICAL: int = 5

# OCSF Status IDs
STATUS_UNKNOWN: int = 0
STATUS_SUCCESS: int = 1
STATUS_FAILURE: int = 2


class OCSFBaseEvent(BaseModel):
    """Base OCSF event with fields common to all event classes."""

    class_uid: int
    category_uid: int
    severity_id: int
    activity_id: int
    type_uid: int
    time: datetime
    message: str
    status_id: int = STATUS_UNKNOWN
    metadata_version: str = OCSF_VERSION
    metadata_product_name: str = PRODUCT_NAME


class AuthenticationEvent(OCSFBaseEvent):
    """OCSF Authentication event (class_uid=3002).

    Maps from cowrie.login.* events.
    """

    src_endpoint_ip: str
    dst_endpoint_ip: str
    user_name: str
    auth_protocol: str
    is_cleartext: bool = True
    logon_type_id: int = 3  # Network logon


class NetworkActivityEvent(OCSFBaseEvent):
    """OCSF Network Activity event (class_uid=4001).

    Maps from nftables firewall logs and fallback events.
    """

    src_endpoint_ip: str
    src_endpoint_port: int
    dst_endpoint_ip: str
    dst_endpoint_port: int
    connection_info_protocol_num: int
    connection_info_direction_id: int = 1  # Inbound
    traffic_bytes_in: int = 0
    traffic_bytes_out: int = 0


class ProcessActivityEvent(OCSFBaseEvent):
    """OCSF Process Activity event (class_uid=1007).

    Maps from cowrie.command.* events.
    """

    actor_process_name: str = "shell"
    actor_process_cmd_line: str
    actor_process_pid: int = 0
    src_endpoint_ip: str


class DetectionFindingEvent(OCSFBaseEvent):
    """OCSF Detection Finding event (class_uid=2004).

    Maps from Suricata alert events.
    """

    finding_title: str
    finding_uid: str
    analytic_name: str = "Suricata"
    analytic_type_id: int = 1  # Rule
    src_endpoint_ip: str
    confidence_id: int = 0
    impact_id: int = 0


class FileActivityEvent(OCSFBaseEvent):
    """OCSF File Activity event (class_uid=1001).

    Maps from cowrie.session.file_download events.
    """

    file_name: str
    file_path: str
    file_size: int = 0
    file_hash_sha256: str = ""
    src_endpoint_ip: str
