"""Typed result shapes for every tool.

The server publishes these as each tool's ``outputSchema`` so a client knows
the row keys before it calls. They are ``TypedDict`` classes rather than
pydantic models for two reasons: a key that a row does not carry stays absent
(rows are compacted, never padded with nulls), and ``extra="allow"`` keeps any
field a dissector adds that is not listed here. Every result may instead be
``{"error": {...}}``; the guard rail in ``server`` never raises to the client.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict
from typing_extensions import TypedDict

_EXTRA_OK = ConfigDict(extra="allow")


class ErrorInfo(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    type: str
    message: str


class ToolResult(TypedDict, total=False):
    """Keys every tool may return: the structured error and the truncation flags."""
    __pydantic_config__ = _EXTRA_OK
    error: ErrorInfo
    truncated: bool
    truncated_reason: str
    warnings: list[str]


class RowsResult(ToolResult, total=False):
    """A capped list of rows: ``count`` rows returned out of ``total_found``.
    ``packets_scanned`` is the number of matching packets the call dissected."""
    count: int
    total_found: int
    packets_scanned: int


# ----------------------------------------------------------------- generic tools
class ProtocolHierarchyEntry(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    protocol: str
    frames: int
    bytes: int


class PcapInfoResult(ToolResult, total=False):
    path: str
    file_size_bytes: int
    file_type: str
    link_type: str
    packets: int | None
    duration_s: float | str
    first_packet: str
    first_packet_epoch: float
    last_packet: str
    last_packet_epoch: float
    capinfos: str
    protocol_hierarchy: list[ProtocolHierarchyEntry]
    limits: dict[str, Any]


class ConversationRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    a: str
    b: str
    frames_a_to_b: int
    bytes_a_to_b: int
    frames_b_to_a: int
    bytes_b_to_a: int
    frames_total: int
    bytes_total: int
    start_rel_s: float
    duration_s: float


class ConversationsResult(RowsResult, total=False):
    conversations: list[ConversationRow]
    layer: str
    display_filter: str | None
    total_frames: int
    total_bytes: int


class FilterPacketsResult(RowsResult, total=False):
    packets: list[dict[str, str]]
    fields: list[str]
    display_filter: str


# ----------------------------------------------------------------- Diameter
class MessageSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    by_message: dict[str, int]
    unanswered: int
    failed: int


class PairedRow(TypedDict, total=False):
    """Keys shared by every request/answer pairing."""
    __pydantic_config__ = _EXTRA_OK
    time: str
    src: str
    dst: str
    request_frame: int
    answer_frame: int
    rtt_ms: float
    unanswered: bool
    unmatched_answer: bool


class DiameterTransactionRow(PairedRow, total=False):
    command_code: int
    command: str
    request: str
    answer: str
    application_id: int
    application: str
    session_id: str
    hop_by_hop: str
    end_to_end: str
    origin_host: str
    origin_realm: str
    destination_host: str
    destination_realm: str
    user_name: str
    retransmitted: bool
    answer_origin_host: str
    result_code: int
    experimental_result_code: int
    result: str
    success: bool
    error_bit: bool


class DiameterTransactionsResult(RowsResult, total=False):
    transactions: list[DiameterTransactionRow]
    summary: MessageSummary


class DiameterSessionTransaction(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    time: str
    request: str
    answer: str
    command_code: int
    command: str
    hop_by_hop: str
    end_to_end: str
    request_frame: int
    answer_frame: int
    result_code: int
    experimental_result_code: int
    result: str
    success: bool
    rtt_ms: float
    unanswered: bool
    unmatched_answer: bool
    retransmitted: bool


class DiameterSessionRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    session_id: str
    first_time: str
    last_time: str
    duration_ms: float
    application_id: int
    application: str
    origin_host: str
    destination_host: str
    origin_realm: str
    destination_realm: str
    user_name: str
    src: str
    dst: str
    transaction_count: int
    request_codes: list[int]
    answer_codes: list[int]
    result_codes: list[int]
    unanswered: int
    failed: int
    max_rtt_ms: float
    transactions: list[DiameterSessionTransaction]


class DiameterSessionSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    sessions: int
    unanswered: int
    failed: int
    without_session_id: int
    by_application: dict[str, int]


class DiameterSessionsResult(RowsResult, total=False):
    sessions: list[DiameterSessionRow]
    summary: DiameterSessionSummary
    selection: str | None


# ----------------------------------------------------------------- GTP
class Fteid(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    interface: str
    teid: str
    ipv4: str
    ipv6: str


class GtpTransactionRow(PairedRow, total=False):
    message: str
    response: str
    seq: int
    teid: str
    imsi: str
    msisdn: str
    apn: str
    rat_type: int
    ebi: int
    request_fteids: list[Fteid]
    note: str
    cause: int
    cause_name: str
    accepted: bool
    paa: str
    response_fteids: list[Fteid]


class GtpSessionsResult(RowsResult, total=False):
    transactions: list[GtpTransactionRow]
    summary: MessageSummary
    selection: str | None


class AddressCount(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    addr: str
    packets: int


class TunnelRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    teid: str
    outer_src: str
    outer_dst: str
    packets: int
    frame_bytes: int
    payload_bytes: int
    first: str
    last: str
    duration_s: float
    inner_src: list[AddressCount]
    inner_dst: list[AddressCount]


class GtpUserPlaneResult(RowsResult, total=False):
    tunnels: list[TunnelRow]
    total_packets: int
    total_payload_bytes: int


# ----------------------------------------------------------------- SIP
class SipMessage(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    dir: str
    method: str
    status: int
    cseq: str
    reason: str


# "from" is a keyword, so this one uses the functional form.
SipDialogRow = TypedDict("SipDialogRow", {
    "call_id": str,
    "time": str,
    "duration_ms": float,
    "src": str,
    "dst": str,
    "initial_method": str,
    "request_uri": str,
    "from": str,
    "to": str,
    "p_asserted_identity": str,
    "final_status": int,
    "time_to_final_ms": float,
    "no_final_response": bool,
    "message_count": int,
    "methods": list[str],
    "messages": list[SipMessage],
}, total=False)
SipDialogRow.__pydantic_config__ = _EXTRA_OK  # type: ignore[attr-defined]


class SipDialogsResult(RowsResult, total=False):
    dialogs: list[SipDialogRow]
    summary: MessageSummary
    selection: str | None


# ----------------------------------------------------------------- SCTP / SIGTRAN
class SctpAssociationRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    endpoint_a: str
    endpoint_b: str
    handshake: str
    init_frame: int
    init_ack_frame: int
    initiate_tags: dict[str, str]
    packets: int
    data_chunks: int
    heartbeats_sent: int
    heartbeats_acked: int
    heartbeats_unacked: int
    retransmissions: int
    abort_seen: bool
    shutdown_seen: bool
    chunk_counts: dict[str, int]
    first: str
    last: str


class SctpAssociationsResult(RowsResult, total=False):
    associations: list[SctpAssociationRow]


class MapComponent(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    type: str
    invoke_id: int
    opcode: int
    operation: str
    error_code: int
    error: str
    problem: str


class SigtranMessageRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    src: str
    dst: str
    m3ua: str
    opc: int
    dpc: int
    sccp: str
    called_gt: str
    called_ssn: int
    calling_gt: str
    calling_ssn: int
    segmentation: dict[str, Any]
    note: str
    tcap: str
    otid: str
    dtid: str
    components: list[MapComponent]
    imsi: str
    msisdn: str
    sms: dict[str, Any]
    answered_in_frame: int
    in_response_to_frame: int
    rtt_ms: float
    unanswered: bool


class SigtranSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    by_operation: dict[str, int]
    unanswered_begins: int
    segmented: int


class SigtranMessagesResult(RowsResult, total=False):
    messages: list[SigtranMessageRow]
    summary: SigtranSummary


# ----------------------------------------------------------------- subscriber trace
class TimelineRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    time: str
    protocol: str
    message: str
    detail: str
    result: str
    identity: str
    src: str
    dst: str
    request_frame: int
    answer_frame: int
    frame: int
    rtt_ms: float
    unanswered: bool
    failed: bool


class SubscriberIdentity(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    imsi: str | None
    msisdn: str | None


class TraceSubscriberResult(RowsResult, total=False):
    timeline: list[TimelineRow]
    identity: SubscriberIdentity
    by_protocol: dict[str, int]
    failures: int
    passes: dict[str, Any]


# ----------------------------------------------------------------- identifier search
class FileHits(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    path: str
    hits: int
    first: str
    last: str
    protocols: dict[str, int]
    truncated: bool
    truncated_reason: str


class FileError(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    path: str
    error: str
    message: str


class FindIdentifierResult(RowsResult, total=False):
    files: list[FileHits]
    identifier: str
    kind: str
    display_filter: str
    files_scanned: int
    files_found: int
    files_with_hits: int
    total_hits: int
    errors: list[FileError]
