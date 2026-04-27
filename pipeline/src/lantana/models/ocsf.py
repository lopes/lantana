"""OCSF (Open Cybersecurity Schema Framework) Pydantic models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class OCSFBaseEvent(BaseModel):
    """Base OCSF event with fields common to all event classes."""

    class_uid: int
    category_uid: int
    severity_id: int
    activity_id: int
    type_uid: int
    time: datetime
    message: str
    status_id: int
    metadata_version: str
    metadata_product_name: str


class AuthenticationEvent(OCSFBaseEvent):
    """OCSF Authentication event (class_uid=3002)."""

    src_endpoint_ip: str
    dst_endpoint_ip: str
    user_name: str
    auth_protocol: str
    is_cleartext: bool
    logon_type_id: int


class NetworkActivityEvent(OCSFBaseEvent):
    """OCSF Network Activity event (class_uid=4001)."""

    src_endpoint_ip: str
    src_endpoint_port: int
    dst_endpoint_ip: str
    dst_endpoint_port: int
    connection_info_protocol_num: int
    connection_info_direction_id: int
    traffic_bytes_in: int
    traffic_bytes_out: int


class ProcessActivityEvent(OCSFBaseEvent):
    """OCSF Process Activity event (class_uid=1007)."""

    actor_process_name: str
    actor_process_cmd_line: str
    actor_process_pid: int
    src_endpoint_ip: str


class DetectionFindingEvent(OCSFBaseEvent):
    """OCSF Detection Finding event (class_uid=2004)."""

    finding_title: str
    finding_uid: str
    analytic_name: str
    analytic_type_id: int
    src_endpoint_ip: str
    confidence_id: int
    impact_id: int


class FileActivityEvent(OCSFBaseEvent):
    """OCSF File Activity event (class_uid=1001)."""

    file_name: str
    file_path: str
    file_size: int
    file_hash_sha256: str
    src_endpoint_ip: str
