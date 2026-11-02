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


class TrimmedList(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    path: str
    kept: int
    of: int


class ToolResult(TypedDict, total=False):
    """Keys every tool may return: the structured error and the truncation flags.
    ``trimmed`` lists the inner lists the output cap shortened (path, items kept, items there were)."""
    __pydantic_config__ = _EXTRA_OK
    error: ErrorInfo
    truncated: bool
    truncated_reason: str
    warnings: list[str]
    trimmed: list[TrimmedList]


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
class TunnelTcp(TypedDict, total=False):
    __pydantic_config__ = _EXTRA_OK
    segments: int
    data_segments: int
    flows: int
    syn: int
    syn_ack: int
    mss_in_syn: dict[str, int]
    retransmissions: int
    retransmission_ratio: float
    fast_retransmissions: int
    duplicate_acks: int
    lost_segments: int
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
