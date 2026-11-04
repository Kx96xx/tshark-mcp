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
    """A tool error, returned with ``isError: true``. ``fix`` says what to change or which
    tool to call next; ``candidates`` lists capture files in the allowed directory a missing
    path pointed into and ``suggestions`` field names close to an unknown one."""
    __pydantic_config__ = _EXTRA_OK
    type: str
    message: str
    fix: str
    candidates: list[str]
    suggestions: list[str]


class TrimmedList(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    path: str
    kept: int
    of: int


class ToolResult(TypedDict, total=False):
    """Keys every tool may return: the structured error and the truncation flags.
    ``trimmed`` lists the inner lists the output cap shortened (path, items kept, items there were).
    ``untrusted_text_fields`` names the keys whose values were copied from packets: data
    from the network, never instructions. Those values are capped (``text_values_shortened``
    counts the ones cut) and every string is stripped of control and bidi characters.
    ``redaction`` is present when identifiers were pseudonymised: the mode, how tokens are
    made, how long they stay stable, ``replaced`` (distinct tokens per kind) and ``complete``
    (false when a capture could not be pre-scanned in full; a warning names it)."""
    __pydantic_config__ = _EXTRA_OK
    error: ErrorInfo
    truncated: bool
    truncated_reason: str
    warnings: list[str]
    trimmed: list[TrimmedList]
    untrusted_text_fields: list[str]
    text_values_shortened: int
    redaction: dict[str, Any]


class RowsResult(ToolResult, total=False):
    """One page of rows. ``total_matched`` rows were found; ``returned`` of them are in
    this page, starting at ``offset``; ``dropped`` come after it and ``next_offset``
    (present when more rows exist) fetches the next page with the same arguments.
    ``total_is_lower_bound`` means a packet or frame cap stopped the scan, so more rows
    exist than were counted and paging cannot reach them: narrow the filter.
    ``count`` and ``total_found`` are the older names of ``returned`` and ``total_matched``.
    ``packets_scanned`` is the number of matching packets the call dissected and
    ``packets_matched`` (when the packet cap stopped it) how many matched in all."""
    count: int
    total_found: int
    total_matched: int
    returned: int
    dropped: int
    offset: int
    next_offset: int
    total_is_lower_bound: bool
    packets_scanned: int
    packets_matched: int


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
    metadata_available: bool
    interface_drops: int


class CopyExample(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    copy_of: int
    cause: str


class Duplicates(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    copies: int
    share: float
    causes: dict[str, int]
    examples: list[CopyExample]


class CaptureGaps(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    tcp_data_segments: int
    missed_by_capture: int
    missed_bytes: int
    directions_with_missed: int
    lost_before_capture: int
    retransmitted_after_capture: int
    out_of_order: int
    unresolved_gaps: int


class TruncatedFrames(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frames: int
    share: float
    snaplen: int
    protocols: dict[str, int]


class OversizedPackets(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    packets: int
    max_ip_len: int
    link_mtu: int


class ChecksumSender(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    sender: str
    bad: int
    packets_sent: int
    layers: dict[str, int]


class Checksums(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    validated: dict[str, int]
    bad: dict[str, int]
    bad_by_sender: list[ChecksumSender]
    bad_tcp_data_segments: int
    bad_tcp_segments_acknowledged: int
    likely_offload: bool
    explanation: str


class OneSided(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    tcp_streams: int
    tcp_one_direction: int
    tcp_one_direction_short: int
    tcp_syn_unanswered: int
    udp_flows: int
    udp_one_way_flows: int
    examples: list[dict[str, Any]]


class TimestampQuality(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    backwards_jumps: int
    max_backwards_s: float
    first_backwards_frame: int
    identical_to_previous: int
    identical_share: float
    resolution: str
    largest_gap_s: float
    largest_gap_after_frame: int
    before_year_2000: int


class QualityVerdict(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    loss_conclusions: str
    summary: str
    reasons: list[str]
    notes: list[str]


class CaptureQualityResult(ToolResult, total=False):
    path: str
    frames: int
    ip_packets: int
    first: str
    last: str
    duration_s: float
    link_types: dict[str, int]
    interfaces: int
    encapsulations: dict[str, int]
    duplicates: Duplicates
    tcp_capture_gaps: CaptureGaps
    truncated_frames: TruncatedFrames
    oversized_packets: OversizedPackets
    checksums: Checksums
    one_sided: OneSided
    timestamps: TimestampQuality
    verdict: QualityVerdict


class TcpHandshake(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    syn: int
    syn_retransmissions: int
    syn_ack: int
    server_side_rtt_ms: float
    client_side_rtt_ms: float
    rtt_ms: float
    client_mss: int
    server_mss: int
    client_wscale: int
    server_wscale: int
    sack: bool


class TcpDirection(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    packets: int
    data_segments: int
    bytes: int
    max_segment: int
    retransmissions: int
    retransmission_ratio: float
    lost_before_capture: int
    retransmitted_after_capture: int
    missed_by_capture: int
    out_of_order: int
    unresolved_gaps: int
    keepalives: int
    duplicate_acks: int
    zero_windows: int
    fin: int
    rst: int


class TcpStreamRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    stream: int
    client: str
    server: str
    first: str
    last: str
    duration_s: float
    packets: int
    copies_dropped: int
    handshake: TcpHandshake
    client_to_server: TcpDirection
    server_to_client: TcpDirection
    resets: list[dict[str, Any]]
    icmp: list[dict[str, Any]]
    df_above_mtu: int
    df_above_mtu_acknowledged: int
    loss: str
    issues: list[str]


class TcpHealthResult(RowsResult, total=False):
    streams: list[TcpStreamRow]
    path_mtu: int
    display_filter: str
    summary: dict[str, int]


class TcpConnectionRow(TypedDict, total=False):
    """One TCP connection attempt. ``outcome``: connected, refused (reset to the SYN),
    filtered (no answer), prohibited (ICMP administratively prohibited), unreachable (other
    ICMP unreachable or time exceeded), reset_during_handshake, handshake_incomplete or
    seen_midway. ``closed_by``: client_fin, server_fin, client_rst, server_rst or
    open_at_capture_end."""
    __pydantic_config__ = _EXTRA_OK
    stream: int
    client: str
    server: str
    outcome: str
    near_capture_end: bool
    syns: int
    syn_retries: int
    syn_retry_gaps_s: list[float]
    connect_ms: float
    bytes_client_to_server: int
    bytes_server_to_client: int
    packets: int
    duration_s: float
    closed_by: str
    completeness: list[str]
    icmp: list[dict[str, Any]]
    reset_frame: int
    first: str
    first_frame: int
    last_frame: int
    copies_dropped: int


class TcpDestinationRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    server: str
    connections: int
    attempts: int
    connected: int
    refused: int
    filtered: int
    prohibited: int
    unreachable: int
    reset_during_handshake: int
    handshake_incomplete: int
    seen_midway: int
    success_rate: float
    syn_retries: int
    connect_ms_p50: float
    connect_ms_max: float
    duration_s_p50: float
    clients: int
    max_concurrent: int
    first_frame: int
    issues: list[str]


class TcpConnectionsResult(RowsResult, total=False):
    view: str
    connections: list[TcpConnectionRow]
    destinations: list[TcpDestinationRow]
class IcmpErrorRow(TypedDict, total=False):
    """ICMP errors from one sender of one kind about one quoted flow (source, destination,
    protocol); ``quoted.ports`` lists the destination ports. ``quoted_flow_seen`` is the frame
    of the quoted original packet, false when the capture does not hold it."""
    __pydantic_config__ = _EXTRA_OK
    sender: str
    kind: str
    error: str
    family: str
    type: int
    code: int
    count: int
    mtu: int
    mtus: list[int]
    quoted: dict[str, Any]
    quoted_ip_id: str
    quoted_flow_seen: int | bool
    first: str
    last: str
    first_frame: int
    last_frame: int


class IcmpErrorsResult(RowsResult, total=False):
    errors: list[IcmpErrorRow]
    by_sender: list[dict[str, Any]]
    echo: list[dict[str, Any]]
    issues: list[str]
    display_filter: str
    summary: dict[str, Any]
class CaptureInterface(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    id: int
    section: int
    name: str
    description: str
    link_type: int
    link_type_name: str
    snaplen: int
    timestamp_resolution: str
    timestamp_offset_s: int
    capture_filter: str
    statistics: dict[str, Any]
    packets: int
    bytes: int
    first: str
    last: str
    truncated_packets: int
    timestamps_backwards: int
    first_packet_after_interface_0_s: float


class CaptureMetadataResult(ToolResult, total=False):
    path: str
    file: dict[str, Any]
    metadata_available: bool
    sections: list[dict[str, Any]]
    writer: dict[str, Any]
    interfaces: list[CaptureInterface]
    packets: int
    drops_total: int
    packet_comments: dict[str, Any]
    issues: list[str]
    read_warnings: list[str]
    note: str
class HttpRequestRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    response_frame: int
    stream: int
    h2_stream: int
    client: str
    server: str
    version: str
    method: str
    host: str
    uri: str
    query: str
    status: int
    reason: str
    content_type: str
    request_bytes: int
    response_bytes: int
    response_ms: float
    ttfb_ms: float
    grpc: bool
    grpc_status: int
    grpc_status_name: str
    stream_reset_by: str
    reset_error: str | int
    unanswered: bool
    near_capture_end: bool


class HttpEndpointRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    host: str
    method: str
    uri: str
    count: int
    status: dict[str, int]
    unanswered: int
    response_ms: dict[str, float]
    response_bytes: dict[str, float]
    grpc_status: dict[str, int]
    servers: list[str]
    slowest_frame: int
    first_frame: int


class HttpTransactionsResult(RowsResult, total=False):
    view: str
    requests: list[HttpRequestRow]
    endpoints: list[HttpEndpointRow]
    display_filter: str
    summary: dict[str, Any]
    undissected_http: list[dict[str, Any]]


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


class PacketDetailResult(ToolResult, total=False):
    """One frame's dissection: ``layers`` maps each protocol to its fields as tshark's
    JSON gives them (a list when the packet carries several PDUs of that protocol)."""
    path: str
    frame: int
    time: str
    length: int
    protocols: str
    layers: dict[str, Any]
    fields_returned: int
    fields_dropped: int
    values_shortened: int
    malformed: bool


class ExpertItem(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    severity: str
    group: str
    protocol: str
    summary: str
    count: int
    first_frame: int
    frames: list[int]
    frame_count: int


class ExpertSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    by_severity: dict[str, int]
    by_protocol: dict[str, int]
    malformed_frames: int
    malformed_first_frames: list[int]


class ExpertInfoResult(RowsResult, total=False):
    items: list[ExpertItem]
    severity: str
    display_filter: str | None
    summary: ExpertSummary


class FieldRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    field: str
    name: str
    type: str
    protocol: str
    display: str
    description: str


class FindFieldsResult(RowsResult, total=False):
    fields: list[FieldRow]
    query: str
    protocol: str | None


class FilterSpan(TypedDict, total=False):
    offset: int
    length: int


class CheckFilterResult(ToolResult, total=False):
    """``valid`` is tshark's verdict; ``errors`` its messages, ``error_at`` the span it
    points at, ``rejected_by`` "server lint" or "tshark". ``filter_warnings`` come from
    dftest when ``warnings_checked``. ``fields`` are the fields the filter names."""
    filter: str
    valid: bool
    errors: list[str]
    error_at: FilterSpan
    rejected_by: str
    filter_warnings: list[str]
    warnings_checked: bool
    fields: list[FieldRow]


class CauseCode(TypedDict, total=False):
    """One code from a ``cause_lookup`` search."""
    __pydantic_config__ = _EXTRA_OK
    code: int | str
    name: str
    avp: str
    explained: bool
    meaning: str


class CauseLookupResult(RowsResult, total=False):
    """One code looked up (``code`` given) or a page of ``codes`` (``query`` given).
    ``name_source`` is "tshark" (its value strings) or "curated" (the server's table);
    ``known`` is false for a code nobody names or one marked reserved; ``explained``
    is false when only the name is known. ``avp`` (Diameter) says whether the code was
    read as a Result-Code or an Experimental-Result-Code; ``also`` gives the other
    reading when the same number exists in both. ``check_next`` names the tool calls
    that find the code in a capture."""
    protocol: str
    code: int | str
    name: str | None
    name_source: str | None
    known: bool
    explained: bool
    avp: str
    application: str
    application_note: str
    by_application: dict[str, str]
    message: str
    message_note: str
    by_message: dict[str, str]
    tshark_field: str
    meaning: str
    ref: str
    typical_causes: list[str]
    related: list[str]
    check_next: list[str]
    also: dict[str, str]
    note: str
    codes: list[CauseCode]
    query: str


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
    legs_without_response: int
    legs_near_capture_end: int
    unanswered_near_capture_end: int
    duplicates: int


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
    leg_without_response: bool
    near_capture_end: bool
    duplicate_of_frame: int
    chain: dict[str, Any]
    note: str


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
    near_capture_end: bool
    note: str
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
    unanswered_near_capture_end: int
    failed: int
    max_rtt_ms: float
    transactions: list[DiameterSessionTransaction]


class DiameterSessionSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    sessions: int
    unanswered: int
    unanswered_near_capture_end: int
    failed: int
    without_session_id: int
    by_application: dict[str, int]


class DiameterSessionsResult(RowsResult, total=False):
    sessions: list[DiameterSessionRow]
    summary: DiameterSessionSummary
    selection: str | None


class DiameterAvpRow(TypedDict, total=False):
    """One paired transaction with its AVPs: the key view (``detail="key"``) or the
    full nested tree (``detail="full"``), where a repeated AVP becomes a list and a
    grouped AVP a nested object."""
    __pydantic_config__ = _EXTRA_OK
    time: str
    request: str
    answer: str
    command: str
    application: str
    session_id: str
    user_name: str
    origin_host: str
    destination_host: str
    answer_origin_host: str
    request_frame: int
    answer_frame: int
    rtt_ms: float
    result: str
    success: bool
    unanswered: bool
    unmatched_answer: bool
    request_avps: dict[str, Any]
    answer_avps: dict[str, Any]
    request_avps_dropped: int
    answer_avps_dropped: int


class DiameterAvpsResult(RowsResult, total=False):
    transactions: list[DiameterAvpRow]
    detail: str
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
    response_path: str


class GtpSessionsResult(RowsResult, total=False):
    transactions: list[GtpTransactionRow]
    summary: MessageSummary
    selection: str | None


class Gtpv1TransactionRow(PairedRow, total=False):
    message: str
    response: str
    seq: int
    teid: str
    imsi: str
    msisdn: str
    apn: str
    nsapi: int
    rat_type: str
    imeisv: str
    request_teid_cp: str
    request_teid_data: str
    request_gsn: str
    cause: int
    cause_name: str
    accepted: bool
    end_user_address: str
    response_teid_cp: str
    response_teid_data: str
    response_gsn: str
    response_path: str


class Gtpv1SessionsResult(RowsResult, total=False):
    transactions: list[Gtpv1TransactionRow]
    summary: MessageSummary
    selection: str | None


class PfcpTransactionRow(PairedRow, total=False):
    message: str
    response: str
    seq: int
    seid: str
    node_id: str
    cp_f_seid: str
    up_f_seid: str
    ue_ip: list[str]
    network_instance: str
    dnn: str
    imsi: str
    rules: dict[str, int]
    far_actions: dict[str, str]
    report_types: list[str]
    usage: list[dict[str, Any]]
    recovery_time: str
    cause: int
    cause_name: str
    accepted: bool
    offending_ie: int
    response_rules: dict[str, int]
    response_usage: list[dict[str, Any]]
    response_recovery_time: str
    response_path: str
    copy_of_frame: int


class PfcpSession(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    cp_seid: str
    up_seid: str
    cp: str
    up: str
    ue_ip: list[str]
    network_instance: str
    dnn: str
    imsi: str
    established: str
    establishment: str
    modifications: int
    failed_modifications: int
    reports: dict[str, int]
    deleted: str
    deletion: str
    unanswered: int
    copies: int
    first: str
    last: str
    usage: dict[str, int]
    usage_reports: int
    issues: list[str]
    state: str


class PfcpNode(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    peers: list[str]
    node_ids: dict[str, str]
    messages: dict[str, int]
    heartbeats: int
    heartbeats_unanswered: int
    recovery_times: dict[str, list[str]]
    restarts: list[str]
    association: str


class PfcpSummary(MessageSummary, total=False):
    sessions: int
    sessions_with_issues: int
    by_state: dict[str, int]
    peer_restarts: int


class PfcpSessionsResult(RowsResult, total=False):
    sessions: list[PfcpSession]
    transactions: list[PfcpTransactionRow]
    summary: PfcpSummary
    nodes: list[PfcpNode]
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
    first_frame: int
    last_frame: int


class GtpUserPlaneResult(RowsResult, total=False):
    tunnels: list[TunnelRow]
    total_packets: int
    total_payload_bytes: int


# ----------------------------------------------------------------- SIP
class TunnelTcp(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    segments: int
    data_segments: int
    flows: int
    syn: int
    syn_ack: int
    mss_in_syn: dict[str, int]
    retransmissions: int
    data_retransmissions: int
    lost_before_capture: int
    retransmitted_after_capture: int
    syn_retransmissions: int
    retransmission_ratio: float
    out_of_order: int
    keepalives: int
    duplicate_acks: int
    zero_windows: int
    resets: int


class TunnelHealthRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    teid: str
    outer_src: str
    outer_dst: str
    packets: int
    frame_bytes: int
    first: str
    last: str
    duration_s: float
    inner_protocols: dict[str, int]
    inner_src: list[str]
    inner_dst: list[str]
    max_outer_ip_len: int
    max_inner_ip_len: int
    tunnel_overhead: int
    inner_df_above_mtu: int
    tcp: TunnelTcp
    icmp: dict[str, int]
    icmp_frag_needed_mtu: dict[str, int]
    reverse_teids: list[str]
    reverse_seen: bool
    issues: list[str]
    first_frame: int
    last_frame: int


class OuterIcmpError(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    error: str
    count: int
    mtu: int
    teids: list[str]
    first: str


class GtpTunnelHealthResult(RowsResult, total=False):
    tunnels: list[TunnelHealthRow]
    path_mtu: int
    summary: dict[str, int]
    outer_icmp: list[OuterIcmpError]


class SipMessage(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    dir: str
    method: str
    status: int
    cseq: str
    reason: str
    resend: bool


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
    "outcome_status": int,
    "attempts": int,
    "resent_messages": int,
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


class SipCallTiming(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    post_dial_delay_ms: float
    post_dial_delay_to: int
    ringing_ms: float
    answer_ms: float
    setup_ms: float
    early_media: str
    call_duration_s: float
    call_duration_note: str


class SipCallDetail(SipDialogRow, total=False):  # type: ignore[misc]
    outcome: str
    caller: str
    final_response: dict[str, Any]
    provisional: list[str]
    timing: SipCallTiming
    retransmissions: dict[str, int]
    reasons: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    ended_by: dict[str, Any]
    media: dict[str, Any]


class SipCallDetailResult(ToolResult, total=False):
    call: SipCallDetail
    found: bool
    packets_scanned: int


# ----------------------------------------------------------------- RTP / media
class SdpMedia(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    media: str
    address: str
    port: int
    proto: str
    codecs: list[str]
    direction: str
    ptime_ms: int
    srtp: bool
    rejected: bool
    private_address: bool


# "from" is a keyword, so this one uses the functional form.
SdpEntry = TypedDict("SdpEntry", {
    "frame": int,
    "time": str,
    "message": str,
    "role": str,
    "from": str,
    "media": list[SdpMedia],
}, total=False)
SdpEntry.__pydantic_config__ = _EXTRA_OK  # type: ignore[attr-defined]


class CallMedia(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    call_id: str
    sdp: list[SdpEntry]


class MosEstimate(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    value: float
    r_factor: float
    estimate: bool
    method: str
    inputs: dict[str, Any]


class RtcpSummary(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    reports: int
    sender_reported_packets: int
    fraction_lost_max_pct: float
    cumulative_lost_last: int
    jitter_max_ms: float
    rtt_ms_max: float
    rtt_ms_mean: float
    rtt_note: str


class RtpStreamRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    ssrc: str
    src: str
    dst: str
    call_id: str
    linked_by: str
    sdp_frame: int
    payload_type: int
    codec: str
    codec_source: str
    clock_rate: int
    payload_types: dict[str, int]
    first_time: str
    last_time: str
    duration_s: float
    first_frame: int
    last_frame: int
    packets: int
    expected: int
    lost: int
    lost_pct: float
    duplicates: int
    sequence_errors: int
    out_of_order: int
    max_delta_ms: float
    mean_delta_ms: float
    max_jitter_ms: float
    mean_jitter_ms: float
    telephone_event_packets: int
    marker_packets: int
    rtcp: RtcpSummary
    mos_estimate: MosEstimate
    reverse_ssrc: str
    one_way: bool
    issues: list[str]


class RtcpXrReport(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    reporter_ssrc: str
    r_factor: int
    mos_lq: float
    mos_cq: float
    round_trip_ms: int


class RtpStreamsResult(RowsResult, total=False):
    streams: list[RtpStreamRow]
    summary: dict[str, Any]
    calls: list[CallMedia]
    rtcp_xr: list[RtcpXrReport]
    mos_method: str
    display_filter: str | None
    notes: list[str]


class MediaIssue(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    kind: str
    detail: str


class MediaDirection(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    direction: str
    expected: str
    status: str
    streams: list[dict[str, Any]]


class MediaPathCheckResult(ToolResult, total=False):
    call_id: str
    found: bool
    offer: dict[str, Any]
    answer: dict[str, Any]
    failure_sdp: dict[str, Any]
    common_codecs: list[str]
    directions: list[MediaDirection]
    issues: list[MediaIssue]
    verdict: str
    rtp_streams: int
    packets_scanned: int
    display_filter: str


class DtmfEventRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    time: str
    frame: int
    source: str
    digit: str
    event: int
    call_id: str
    src: str
    dst: str
    ssrc: str
    payload_type: int
    clock_rate: int
    duration_ms: float
    volume_dbm0: int
    packets: int
    end_packets: int
    content_type: str
    response: int
    issues: list[str]


class DtmfEventsResult(RowsResult, total=False):
    events: list[DtmfEventRow]
    summary: dict[str, int]
    calls: list[dict[str, Any]]


# ----------------------------------------------------------------- IMS registration
class ImsRegisterStep(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    time: str
    frame: int
    kind: str
    call_id: str
    cseq: int
    requested_expires: int
    auth: str
    status: int
    reason_phrase: str
    status_frame: int
    rtt_ms: float
    granted_expires: int
    challenge_algorithm: str
    retry_after: int
    min_expires: int
    warning: str
    other_leg_statuses: list[int]
    legs: int
    retransmissions: int
    copies: int
    no_final_response: bool


class ImsRegistrationRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    impu: str
    impi: str
    first_time: str
    first_frame: int
    last_time: str
    verdict: str
    reasons: list[str]
    registered_until: str
    time_to_register_ms: float
    user_agent: str
    contact: str
    feature_tags: list[str]
    smsip: bool
    mmtel: bool
    sec_agree: list[str]
    associated_uris: list[str]
    service_route: list[str]
    path_header: list[str]
    counts: dict[str, int]
    transactions: list[ImsRegisterStep]
    third_party: list[dict[str, Any]]
    reg_event_notifies: list[dict[str, Any]]


class ImsRegistrationResult(RowsResult, total=False):
    registrations: list[ImsRegistrationRow]
    summary: dict[str, Any]
    capture_end: str


class SmsAck(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    rp_message: str
    frame: int
    time: str
    call_id: str
    delay_ms: float
    rp_cause: int
    rp_cause_name: str
    tpdu: dict[str, Any]
    sip_response: int
    sip_response_frame: int
    no_sip_response: bool
    retransmissions: int


class SmsOverImsRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    time: str
    frame: int
    direction: str
    rp_message: str
    rp_mr: int
    call_id: str
    request_uri: str
    smsc_digits: str
    tpdu: dict[str, Any]
    status_report_of_frame: int
    sip_response: int
    sip_response_frame: int
    sip_response_ms: float
    other_leg_statuses: list[int]
    legs: int
    retransmissions: int
    copies: int
    ack: SmsAck
    status_report: dict[str, Any]
    ue_registration: dict[str, Any]
    verdict: str
    reasons: list[str]


class SmsOverImsResult(RowsResult, total=False):
    messages: list[SmsOverImsRow]
    summary: dict[str, Any]
    capture_end: str


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
    first_frame: int
    last_frame: int
    abort_frame: int


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
    leg_without_response: bool
    near_capture_end: bool
    duplicate_of_frame: int
    chain: dict[str, Any]
    note: str


class SubscriberIdentity(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    imsi: str | None
    msisdn: str | None


class TraceSubscriberResult(RowsResult, total=False):
    timeline: list[TimelineRow]
    identity: SubscriberIdentity
    by_protocol: dict[str, int]
    failures: int
    unanswered_near_capture_end: int
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
    first_frame: int
    last_frame: int


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
    partially_scanned: list[str]
    files_not_scanned: int


# ----------------------------------------------------------------- capture comparison
class LadderStep(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    index: int
    time: str
    offset_s: float
    protocol: str
    message: str
    result: str
    rtt_ms: float
    request_frame: int
    answer_frame: int
    unanswered: bool
    failed: bool
    repeat: int


class LadderEntry(TypedDict, total=False):
    """One aligned position: ``op`` is same, changed, replaced, only_a or only_b;
    ``differences`` maps a field (``result``, ``answer_avps.ULA-Flags``, ``apn``, ...)
    to its value in each capture."""
    __pydantic_config__ = _EXTRA_OK
    op: str
    a: LadderStep
    b: LadderStep
    differences: dict[str, Any]
    ladder_position: int
    after: list[str]


class CaptureSide(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    path: str
    identity: dict[str, str] | None
    steps: int
    messages: int
    duration_s: float | None
    by_protocol: dict[str, int]
    unanswered: int
    failed: int
    passes: dict[str, Any]


class CompareCapturesResult(RowsResult, total=False):
    ladder: list[LadderEntry]
    a: CaptureSide
    b: CaptureSide
    summary: dict[str, int]
    first_divergence: LadderEntry | None
    identical: bool
    timing: dict[str, Any]
    notes: list[str]


# ----------------------------------------------------------------- rates
class MessageRate(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    protocol: str
    message: str
    request: bool | None
    total: int
    distinct: int
    peak: int
    peak_at: str
    mean_per_s: float
    active_intervals: int
    bursts: int
    first_frame: int


class Burst(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    protocol: str
    message: str
    start: str
    end: str
    duration_s: float
    messages: int
    peak_per_interval: int
    baseline_per_interval: float


class SubscriberLoop(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    subscriber: str
    protocol: str
    message: str
    count: int
    first: str
    last: str
    span_s: float
    median_gap_s: float
    min_gap_s: float
    max_gap_s: float
    regular: bool
    first_frame: int
    last_frame: int
    from_nodes: list[dict[str, Any]]
    to_nodes: list[dict[str, Any]]
    alternating: str


class MessageRatesResult(RowsResult, total=False):
    protocol: str
    interval_s: float
    display_filter: str
    packets_scanned: int
    messages: int
    distinct_messages: int
    copies: int
    attributed_messages: int
    first: str
    last: str
    duration_s: float
    by_message: list[MessageRate]
    bursts: list[Burst]
    bursts_total: int
    subscriber_loops: list[SubscriberLoop]
    timeline: list[dict[str, Any]]
    timeline_interval_s: float
    storms: list[str]


# ----------------------------------------------------------------- DNS
class DnsTransactionRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    client: str
    server: str
    transport: str
    id: str
    name: str
    type: str
    response_frame: int
    rcode: int
    rcode_name: str
    answers: int
    addresses: list[str]
    cnames: list[str]
    rtt_ms: float
    unanswered: bool
    near_capture_end: bool
    note: str
    retransmissions: int
    retry_of: int
    truncated_tc: bool
    tcp_fallback_frame: int
    fallback_from_udp: bool
    duplicate_responses: int


class DnsServerRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    server: str
    queries: int
    answered: int
    unanswered: int
    unanswered_share: float
    rcodes: dict[str, int]
    retransmissions: int
    transports: dict[str, int]
    clients: int
    icmp_errors: int
    rtt_ms: dict[str, float]


class DnsNameRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    name: str
    queries: int
    unanswered: int
    failed: int
    rcodes: dict[str, int]
    retries: int
    slow: int
    types: list[str]
    servers: list[str]


class DnsTransactionsResult(RowsResult, total=False):
    transactions: list[DnsTransactionRow]
    servers: list[DnsServerRow]
    names: list[DnsNameRow]
    summary: dict[str, Any]
    issues: list[str]


# ----------------------------------------------------------------- TLS
class TlsAlert(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    level: str
    description: str
    frame: int
    quic: bool


class TlsCertificate(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    subject_cn: str
    subject_o: str
    issuer_cn: str
    issuer_o: str
    san: list[str]
    san_total: int
    not_before: str
    not_after: str
    chain_length: int


class TlsHandshakeRow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    transport: str
    stream: int
    client: str
    server: str
    frame: int
    time: str
    sni: str
    offered: dict[str, Any]
    client_hellos: int
    client_hello_missing: bool
    hello_retry_request: bool
    chosen: dict[str, Any]
    tcp_to_hello_ms: float
    server_hello_ms: float
    alerts: list[TlsAlert]
    certificate: TlsCertificate
    outcome: str
    note: str
    closed: dict[str, str]
    duplicate_copies: int
    issues: list[str]


class TlsHandshakesResult(RowsResult, total=False):
    connections: list[TlsHandshakeRow]
    summary: dict[str, Any]
    issues: list[str]


# ----------------------------------------------------------------- TCP response times
class TcpExchange(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    frame: int
    time: str
    h2_stream: int
    method: str
    uri: str
    host: str
    status: int
    grpc_status: int
    stream_reset_by: str
    request_bytes: int
    request_ms: float
    response_frame: int
    response_bytes: int
    think_ms: float
    server_ms: float
    transfer_ms: float
    total_ms: float
    retransmissions: int
    out_of_order: int
    stalls: list[dict[str, Any]]
    no_response: bool
    long_wait: bool


class ResponseTimeFlow(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    stream: int
    tcp_streams: list[int]
    http2: bool
    client: str
    server: str
    frame: int
    first: str
    duration_ms: float
    rtt_ms: float
    rtt_capture_to_server_ms: float
    rtt_capture_to_client_ms: float
    rtt_source: str
    connect_ms: float
    syn_retransmissions: int
    synack_retransmissions: int
    capture_near: str
    exchanges: int
    unanswered_requests: int
    long_waits: int
    server_pushes: int
    max_server_ms: float
    time_split_ms: dict[str, float]
    verdict: str
    why: str
    retransmissions: int
    out_of_order: int
    zero_windows: int
    resets: dict[str, int]
    closed: dict[str, str]
    duplicate_copies: int
    slowest_exchanges: list[TcpExchange]


class ResponseTimesResult(RowsResult, total=False):
    flows: list[ResponseTimeFlow]
    servers: list[dict[str, Any]]
    not_opened: list[dict[str, Any]]
    summary: dict[str, Any]
    issues: list[str]
