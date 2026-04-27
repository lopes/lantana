"""Tests for OCSF Pydantic models -- schema contract validation."""

from __future__ import annotations

from datetime import datetime, timezone

from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    OCSF_VERSION,
    PRODUCT_NAME,
    AuthenticationEvent,
    DetectionFindingEvent,
    FileActivityEvent,
    NetworkActivityEvent,
    OCSFBaseEvent,
    ProcessActivityEvent,
)


def _ts() -> datetime:
    return datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)


def test_base_event_defaults() -> None:
    """Base event has correct defaults for metadata fields."""
    event = OCSFBaseEvent(
        class_uid=4001,
        category_uid=4,
        severity_id=1,
        activity_id=1,
        type_uid=400101,
        time=_ts(),
        message="test",
    )
    assert event.metadata_version == OCSF_VERSION
    assert event.metadata_product_name == PRODUCT_NAME
    assert event.status_id == 0


def test_authentication_event() -> None:
    """AuthenticationEvent with all required fields."""
    event = AuthenticationEvent(
        class_uid=CLASS_AUTHENTICATION,
        category_uid=3,
        severity_id=3,
        activity_id=1,
        type_uid=CLASS_AUTHENTICATION * 100 + 1,
        time=_ts(),
        message="login attempt",
        status_id=1,
        src_endpoint_ip="203.0.113.50",
        dst_endpoint_ip="10.50.99.100",
        user_name="root",
        auth_protocol="ssh",
    )
    assert event.class_uid == 3002
    assert event.is_cleartext is True
    assert event.logon_type_id == 3
    assert event.type_uid == 300201


def test_network_activity_event() -> None:
    """NetworkActivityEvent with all required fields."""
    event = NetworkActivityEvent(
        class_uid=CLASS_NETWORK_ACTIVITY,
        category_uid=4,
        severity_id=1,
        activity_id=6,
        type_uid=CLASS_NETWORK_ACTIVITY * 100 + 6,
        time=_ts(),
        message="packet dropped",
        src_endpoint_ip="203.0.113.50",
        src_endpoint_port=54321,
        dst_endpoint_ip="10.50.99.100",
        dst_endpoint_port=23,
        connection_info_protocol_num=6,
    )
    assert event.class_uid == 4001
    assert event.connection_info_direction_id == 1
    assert event.traffic_bytes_in == 0


def test_process_activity_event() -> None:
    """ProcessActivityEvent with all required fields."""
    event = ProcessActivityEvent(
        class_uid=CLASS_PROCESS_ACTIVITY,
        category_uid=1,
        severity_id=3,
        activity_id=1,
        type_uid=CLASS_PROCESS_ACTIVITY * 100 + 1,
        time=_ts(),
        message="CMD: uname -a",
        src_endpoint_ip="203.0.113.50",
        actor_process_cmd_line="uname -a",
    )
    assert event.class_uid == 1007
    assert event.actor_process_name == "shell"
    assert event.actor_process_pid == 0


def test_detection_finding_event() -> None:
    """DetectionFindingEvent with all required fields."""
    event = DetectionFindingEvent(
        class_uid=CLASS_DETECTION_FINDING,
        category_uid=2,
        severity_id=4,
        activity_id=1,
        type_uid=CLASS_DETECTION_FINDING * 100 + 1,
        time=_ts(),
        message="ET SCAN Potential SSH Scan",
        src_endpoint_ip="203.0.113.50",
        finding_title="ET SCAN Potential SSH Scan",
        finding_uid="2001219",
    )
    assert event.class_uid == 2004
    assert event.analytic_name == "Suricata"
    assert event.analytic_type_id == 1


def test_file_activity_event() -> None:
    """FileActivityEvent with all required fields."""
    event = FileActivityEvent(
        class_uid=CLASS_FILE_ACTIVITY,
        category_uid=1,
        severity_id=4,
        activity_id=2,
        type_uid=CLASS_FILE_ACTIVITY * 100 + 2,
        time=_ts(),
        message="file download",
        src_endpoint_ip="203.0.113.50",
        file_name="malware.sh",
        file_path="/tmp/malware.sh",
    )
    assert event.class_uid == 1001
    assert event.file_size == 0
    assert event.file_hash_sha256 == ""


def test_type_uid_convention() -> None:
    """type_uid should follow class_uid * 100 + activity_id convention."""
    for cls_uid, activity in [
        (CLASS_AUTHENTICATION, 1),
        (CLASS_NETWORK_ACTIVITY, 6),
        (CLASS_PROCESS_ACTIVITY, 1),
        (CLASS_DETECTION_FINDING, 1),
        (CLASS_FILE_ACTIVITY, 2),
    ]:
        expected = cls_uid * 100 + activity
        event = OCSFBaseEvent(
            class_uid=cls_uid,
            category_uid=1,
            severity_id=1,
            activity_id=activity,
            type_uid=expected,
            time=_ts(),
            message="test",
        )
        assert event.type_uid == expected
