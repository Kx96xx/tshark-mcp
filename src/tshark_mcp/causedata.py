"""Curated text for ``cause_lookup``: what a cause code means, where the spec defines
it, what usually produces it and which tool to run next.

The *names* of most codes are not written here: ``causes.py`` reads them from
tshark's own value strings (``tshark -G values``), so a name always matches what
the dissector prints. Only protocols tshark has no value table for (SIP status
codes, MAP errors, CP causes, TP-Status, SBI ProblemDetails causes) carry names in
this file. ``tests/test_cause_lookup.py`` checks that every code tshark names has
an entry here or is listed in :data:`UNEXPLAINED`, so a new tshark release that
adds a code fails the suite instead of drifting silently.

Entry shape: ``code: (meaning, typical_causes, related)`` or a dict with the keys
``meaning``, ``typical``, ``related``, ``ref``, ``name``, ``next``, ``by_message``
and ``by_application``. Text is the spec's meaning shortened, plus field
experience; it never quotes subscriber data.
"""

from __future__ import annotations

from typing import Any

Entry = Any  # tuple[str, tuple[str, ...], tuple[str, ...]] | dict[str, Any]

# ----------------------------------------------------------------- GTPv2-C
GTPV2: dict[int, Entry] = {
    16: ("The request was accepted in full.", (), ()),
    17: ("Accepted, but some bearers or parts of the request were not: read the cause inside each Bearer Context.",
         ("one bearer of several rejected (QoS, TFT or resources)",), ("16",)),
    18: ("Accepted with a different PDN type than requested, by network preference (the UE asked IPv4v6 and got "
         "IPv4 or IPv6 only).", ("APN configured single-stack", "operator policy prefers one family"), ("19", "83")),
    19: ("Accepted with a different PDN type because the network supports single-address bearers only.",
         ("dual-stack requested on a node or roaming partner without dual-address bearers",), ("18",)),
    64: ("The receiver has no context for the TEID in the GTP header.",
         ("the peer restarted and lost its sessions (Recovery IE changed)", "the session was already deleted",
          "a proxy or NAT rewrote the TEID or sent the message to the wrong node"),
         ("66", "PFCP 65")),
    65: ("The message could not be decoded.", ("encoding bug or truncated message",), ("67", "69")),
    66: ("The next peer does not support this GTP version.", ("GTPv2 sent to a GTPv1-only node",), ("108",)),
    67: ("A length field is wrong.", ("encoding bug", "message truncated by an intermediate node"), ("65",)),
    68: ("The receiver does not support the requested service or message.", ("feature not enabled on the peer",), ()),
    69: ("A mandatory IE is present but its value is wrong; the Offending IE in the response names it.",
         ("APN, PDN type or F-TEID encoded wrongly", "a value outside the allowed range"), ("70", "103")),
    70: ("A mandatory IE is missing; the Offending IE names it.",
         ("sender software bug", "interworking between releases"), ("69", "103")),
    72: ("Generic failure inside the receiver.", ("software fault", "internal timeout to a backend (AAA, PCRF, IP pool)"),
         ("73",)),
    73: ("The receiver has no resources for the request.",
         ("IP pool or session capacity exhausted on the PGW/SGW", "overload",
          "a PDN type the APN cannot serve (some PGWs answer 73 to IPv4v6 or IPv6 on an IPv4-only APN)"),
         ("84", "120")),
    78: ("The APN in the request is not known to the gateway (or its configuration).",
         ("the MME sent a different APN than the gateway serves (check the APN Network Identifier and the OI)",
          "APN missing on this PGW, or DNS chose the wrong PGW",
          "the subscription holds a different APN than the UE asked for"),
         ("93", "ESM 27", "Diameter 5451")),
    80: ("The GRE key in the request is not known (PMIP-based S5/S8).", ("stale session after a restart",), ("64",)),
    81: ("Relocation (handover or SGW change) failed.", ("target SGW or MME could not take the context",), ()),
    82: ("The service is not allowed on the current RAT.", ("subscription or APN limited to other RATs",), ("Diameter 5421",)),
    83: ("The PDN type the UE prefers is not supported.", ("IPv6 requested where only IPv4 is configured",), ("18", "19")),
    84: ("All dynamic addresses of the pool are in use.", ("IP pool exhausted", "stale sessions holding addresses"),
         ("73", "PFCP 79")),
    87: ("The UE did not answer paging.", ("UE out of coverage or switched off", "UE in PSM"), ("90", "123")),
    88: ("The UE refused the network-initiated request.", (), ("87",)),
    89: ("The request is not allowed by policy.", ("operator or partner policy, roaming restriction",), ("93",)),
    90: ("The UE could not be paged.", ("UE detached or unreachable",), ("87", "102")),
    91: ("The receiver is out of memory.", ("overload",), ("73",)),
    92: ("The PGW's user authentication failed.",
         ("RADIUS or Diameter AAA rejected the user name and password from the PCO (PAP/CHAP)",
          "the PCRF or OCS refused the session"),
         ("125", "Diameter 4001")),
    93: ("The subscriber has no subscription for this APN.",
         ("APN not in the subscription the HSS sent (check the ULA Subscription-Data)",
          "visited network refusing the APN by policy"),
         ("78", "Diameter 5451")),
    94: ("Rejected without a specific reason.", ("gateway policy or an internal failure mapped to the generic code",),
         ("72",)),
    96: ("The IMSI or IMEI is not known to the receiver.", ("context lost after a restart",), ("64",)),
    100: ("The next peer did not answer.", ("PGW unreachable from the SGW, or a proxy lost its upstream",),
          ("107",)),
    101: ("This request collided with a request the network started for the same session.",
          ("simultaneous Modify Bearer and Update Bearer",), ()),
    103: ("A conditional IE needed here is missing; the Offending IE names it.",
          ("e.g. no Sender F-TEID for Control Plane on a Create Session to a new SGW",), ("70",)),
    104: ("The APN Restriction of this APN conflicts with an active PDN connection.", (), ()),
    107: ("The next peer answered with something invalid.", ("proxy or SGW relaying a broken response",), ("100",)),
    110: ("Temporarily rejected because a handover, TAU or RAU is in progress; retry afterwards.", (), ("101",)),
    113: ("The APN is congested; a back-off timer may follow.", ("APN-level overload control at the PGW",), ("120",)),
    116: ("The UE may not open a second PDN connection to the same APN.", (), ()),
    117: ("The subscriber may not use the target access.", ("Access-Restriction-Data in the subscription",),
          ("Diameter 5421",)),
    119: ("The MME/SGSN refused because of the visited network's policy.", ("VPLMN policy for home-routed sessions",), ()),
    120: ("The GTP-C entity is congested (overload control).", ("node overload",), ("113", "73")),
    122: ("The request timed out inside the receiver.", ("backend (PCRF, AAA, PFCP) too slow",), ("100",)),
    123: ("The UE is in power saving mode and not reachable now.", (), ("87",)),
    125: ("The OCS or an external AAA server did not authorise the UE.", ("no credit", "AAA reject"), ("92",)),
}

# ----------------------------------------------------------------- GTPv1-C
GTPV1: dict[int, Entry] = {
    128: ("The request was accepted.", (), ()),
    129: ("Accepted with a different PDP type by network preference.", ("APN configured single-stack",), ("130",)),
    130: ("Accepted with a different PDP type: single-address bearers only.", (), ("129",)),
    192: ("The receiver has no context for this TEID (non-existent).",
          ("the GGSN restarted (Recovery changed) or already deleted the context",), ("210", "GTPv2 64")),
    193: ("The message could not be decoded.", (), ("201", "202")),
    194: ("The IMSI is not known.", (), ()),
    199: ("No resources available at the GGSN or SGSN.", ("IP pool or capacity exhausted",), ("211", "GTPv2 73")),
    200: ("The service is not supported.", (), ()),
    201: ("A mandatory IE has a wrong value.", (), ("202",)),
    202: ("A mandatory IE is missing.", (), ("201",)),
    204: ("Generic system failure.", ("internal fault or a backend timeout",), ()),
    205: ("Roaming restriction.", ("the subscriber may not roam in this network",), ()),
    209: ("User authentication failed at the GGSN.", ("RADIUS rejected the PAP/CHAP credentials from the PCO",),
          ("GTPv2 92",)),
    210: ("Context not found.", ("context deleted or lost after a restart",), ("192",)),
    211: ("All dynamic PDP addresses are in use.", ("IP pool exhausted",), ("199", "GTPv2 84")),
    219: ("The APN is missing or unknown at the GGSN.", ("APN not configured, or the SGSN resolved the wrong GGSN",),
          ("GTPv2 78",)),
    220: ("The PDP address or PDP type is unknown.", ("IPv6 or IPv4v6 asked on an IPv4-only APN",), ()),
    222: ("No subscription for this APN.", ("APN absent from the HLR/HSS subscription",), ("GTPv2 93",)),
    229: ("The APN is congested.", (), ("GTPv2 113",)),
}

# ----------------------------------------------------------------- PFCP
PFCP: dict[int, Entry] = {
    1: ("The request was accepted.", (), ()),
    3: ("Accepted in part; read the rule-level results (Failed Rule ID).", (), ("73",)),
    64: ("Rejected without a specific reason.", (), ()),
    65: ("The UP function has no session for this SEID.",
         ("the UPF restarted (Recovery Time Stamp changed)", "the session was already deleted",
          "the SMF used a stale SEID after its own restart"), ("72", "GTPv2 64")),
    66: ("A mandatory IE is missing; the Offending IE names it.", (), ("69",)),
    67: ("A conditional IE is missing; the Offending IE names it.", (), ("66",)),
    69: ("A mandatory IE is present but wrong; the Offending IE names it.", (), ("66",)),
    72: ("No PFCP association exists between the two nodes.",
         ("association setup never completed", "association lost after a restart or heartbeat failure"), ("65",)),
    73: ("A PDR, FAR, QER, URR or BAR could not be created or modified; Failed Rule ID names it.",
         ("unknown network instance or APN/DNN on the UPF", "F-TEID allocation failed", "unsupported rule feature"),
         ("71", "80")),
    74: ("The UP function is congested.", (), ("75",)),
    75: ("No resources available on the UP function.", ("session capacity or memory exhausted",), ("79",)),
    77: ("Generic failure inside the UP function.", (), ()),
    79: ("All dynamic UE addresses of the UP pool are in use.", ("UPF-allocated IP pool exhausted",), ("GTPv2 84",)),
    80: ("A pre-defined rule named by the SMF does not exist on the UPF.", ("rule configured on the PCRF/SMF only",),
         ("81",)),
    81: ("An Application ID named by the SMF is unknown to the UPF.", (), ("80",)),
}

# ----------------------------------------------------------------- NAS EPS mobility management
EMM: dict[int, Entry] = {
    2: ("The HSS does not know the IMSI (EPS attach refused, non-EPS may continue).",
        ("IMSI not provisioned in the HSS", "wrong IMSI range routed to this HSS"), ("Diameter 5001", "3", "8")),
    3: {"meaning": "The UE is not acceptable to the network (the SIM is considered invalid until power cycle).",
        "typical": ("authentication failed: the network's RES check failed", "the HSS returned 5001 after authentication"),
        "related": ("6", "Diameter 5004")},
    5: ("The IMEI was not accepted (emergency attach only).", ("EIR blacklist via S13",), ("6", "Diameter 5422")),
    6: ("The ME is not acceptable to the network (SIM invalid until power cycle).", ("EIR blacklist",), ("3", "5")),
    7: {"meaning": "The UE may not use EPS services; the SIM is invalid for EPS until power cycle.",
        "typical": ("no EPS subscription", "HSS answered 5420 UNKNOWN_EPS_SUBSCRIPTION"),
        "related": ("8", "14", "Diameter 5420")},
    8: ("Neither EPS nor non-EPS services are allowed.", ("no subscription at all for this network",), ("7",)),
    9: ("The network cannot derive the UE identity from the GUTI; the UE should attach again with its IMSI.",
        ("the old MME is unreachable or lost the context",), ("10",)),
    10: ("The network has implicitly detached the UE; the UE should re-attach.", ("mobile reachable timer expired",),
         ("9",)),
    11: {"meaning": "The PLMN is not allowed; the UE stores it as forbidden and selects another network.",
         "typical": ("no roaming agreement or roaming barred for this subscriber",
                     "HSS answered 5004 ROAMING_NOT_ALLOWED"),
         "related": ("13", "14", "Diameter 5004")},
    12: ("The tracking area is not allowed (stored as forbidden for regional provision of service).",
         ("regional subscription restriction",), ("13", "15")),
    13: ("Roaming is not allowed in this tracking area; the UE searches for another PLMN.",
         ("national roaming restricted to some areas",), ("11", "12")),
    14: {"meaning": "EPS services are not allowed in this PLMN; the UE may still use CS/2G/3G here.",
         "typical": ("LTE roaming not agreed with this partner while 2G/3G roaming is", "ODB or Access-Restriction-Data"),
         "related": ("11", "7", "Diameter 5004")},
    15: ("No suitable cells in this tracking area; the UE looks for another TA in the same PLMN.",
         ("RAT or area restriction",), ("12", "13")),
    16: ("The MSC is temporarily unreachable (combined attach: EPS ok, CS later).", ("SGs association down",),
         ("17", "SGsAP")),
    17: ("Network failure.", ("HSS or SGs failure seen by the MME",), ("16",)),
    18: ("The CS domain is not available (combined attach accepted for EPS only).", (), ("16",)),
    19: ("The ESM procedure piggy-backed on attach failed; read the ESM cause in the same message.",
         ("PDN connectivity rejected: APN, PDN type or gateway failure",), ("ESM 27", "ESM 33", "GTPv2 78")),
    20: ("The network's AUTN failed the UE's MAC check.", ("the AUTN came from the wrong HSS or keys",), ("21",)),
    21: ("Sequence number out of range at the USIM: a resynchronisation (AUTS) follows.",
         ("SQN in the HSS behind the USIM",), ("20",)),
    22: ("The network is congested; a back-off timer T3346 may follow.", ("MME overload control",), ()),
    25: ("Not authorised for this CSG.", (), ()),
    35: ("The requested service option is not authorised in this PLMN.", (), ()),
    40: ("No EPS bearer context is active; the UE must re-attach.", (), ()),
    42: ("Severe network failure; the UE should not retry for a while.", (), ("17",)),
    95: ("Semantically incorrect message.", (), ("96",)),
    96: ("Invalid mandatory information.", (), ("95",)),
    111: ("Protocol error, unspecified.", (), ()),
}

ESM: dict[int, Entry] = {
    8: ("Operator determined barring stops this PDN connection.", ("ODB in the subscription",), ("Diameter 5004",)),
    26: ("Insufficient resources.", ("gateway or bearer resources exhausted",), ("GTPv2 73",)),
    27: ("The APN is missing or unknown.", ("APN not subscribed and no default", "GTPv2 78 from the gateway"),
         ("GTPv2 78", "33")),
    28: ("The PDN type is unknown.", (), ("50", "51")),
    29: ("User authentication or authorisation failed.", ("PGW AAA rejected the PAP/CHAP credentials (GTPv2 92)",),
         ("GTPv2 92",)),
    30: ("The SGW or PGW rejected the request.", ("read the GTPv2 cause of the matching Create Session Response",),
         ("GTPv2 94",)),
    31: ("Rejected, unspecified.", (), ("30",)),
    32: ("The service option is not supported.", (), ()),
    33: ("The requested service option is not subscribed (e.g. the APN is not in the subscription).",
         ("APN absent from the HSS Subscription-Data", "GTPv2 93"), ("27", "GTPv2 93")),
    34: ("The service option is temporarily out of order.", (), ()),
    36: ("Regular deactivation of the bearer or PDN connection.", (), ()),
    37: ("The EPS QoS was not accepted.", (), ()),
    38: ("Network failure.", ("gateway failure after Create Session",), ()),
    39: ("Reactivation requested: the UE should reconnect to the APN.", ("PGW restart or APN rebalancing",), ()),
    50: ("Only IPv4 is allowed for this APN.", ("the UE asked IPv4v6 or IPv6",), ("51", "GTPv2 18")),
    51: ("Only IPv6 is allowed for this APN.", (), ("50",)),
    52: ("Only single-address bearers are allowed.", (), ("GTPv2 19",)),
    53: ("The ESM information (APN, PCO) was not received from the UE.", ("ESM information request unanswered",), ()),
    54: ("The PDN connection does not exist.", (), ()),
    55: ("A second PDN connection to the same APN is not allowed.", (), ("GTPv2 116",)),
    65: ("The maximum number of EPS bearers is reached.", (), ()),
    66: ("The APN is not supported in this RAT and PLMN combination.", (), ()),
    112: ("The APN restriction is incompatible with an active bearer context.", (), ("GTPv2 104",)),
}

FIVEG_MM: dict[int, Entry] = {
    3: ("Illegal UE: the SIM is invalid for 5GS until power cycle.", ("authentication failed",), ("EMM 3",)),
    7: ("5GS services are not allowed.", ("no 5GS subscription",), ("EMM 7",)),
    9: ("The network cannot derive the UE identity; the UE registers again with SUCI.", (), ("10",)),
    10: ("Implicitly deregistered.", (), ("9",)),
    11: ("PLMN not allowed.", ("no roaming agreement or roaming barred",), ("EMM 11",)),
    12: ("Tracking area not allowed.", (), ("13",)),
    13: ("Roaming not allowed in this tracking area.", (), ("11",)),
    15: ("No suitable cells in tracking area.", (), ()),
    22: ("Congestion; a back-off timer follows.", (), ()),
    27: ("N1 mode not allowed: the UE should use EPS.", (), ("31",)),
    31: ("Redirection to EPC required.", (), ("27",)),
    62: ("No network slices available: none of the requested S-NSSAIs is allowed.", ("slice not subscribed",), ("91",)),
    65: ("Maximum number of PDU sessions reached.", (), ()),
    72: ("Non-3GPP access to 5GCN not allowed.", (), ()),
    73: ("The serving network is not authorised (the home network refused it in the authentication).", (), ("11",)),
    91: ("The DNN is not supported or not subscribed in the slice.", (), ("5GSM 27", "62")),
}

FIVEG_SM: dict[int, Entry] = {
    8: ("Operator determined barring.", (), ("ESM 8",)),
    26: ("Insufficient resources.", ("SMF or UPF resources exhausted",), ("PFCP 75",)),
    27: ("The DNN is missing or unknown.", ("DNN not configured on the SMF",), ("ESM 27", "70")),
    28: ("Unknown PDU session type.", (), ("50", "51")),
    29: ("User authentication or authorisation failed.", ("secondary authentication or AAA reject",), ("ESM 29",)),
    31: ("Rejected, unspecified.", (), ()),
    33: ("The requested service option is not subscribed.", ("DNN or S-NSSAI not in the UDM subscription",), ()),
    36: ("Regular deactivation.", (), ()),
    38: ("Network failure.", ("N4/PFCP or N11 failure behind the SMF",), ()),
    39: ("Reactivation requested.", (), ()),
    50: ("Only IPv4 PDU sessions are allowed.", (), ("ESM 50",)),
    51: ("Only IPv6 PDU sessions are allowed.", (), ("ESM 51",)),
    54: ("The PDU session does not exist.", (), ()),
    67: ("Insufficient resources for the slice and DNN.", (), ("69",)),
    69: ("Insufficient resources for the slice.", (), ("67",)),
    70: ("The DNN is missing or unknown in this slice.", (), ("27",)),
}

# ----------------------------------------------------------------- S1AP / NGAP (keyed "group:value")
S1AP: dict[str, Entry] = {
    "radioNetwork:20": ("User inactivity: the eNB released an idle UE (normal).", (), ()),
    "radioNetwork:21": ("The radio connection with the UE was lost.", ("coverage loss", "RLF without re-establishment"),
                        ("radioNetwork:26",)),
    "radioNetwork:23": ("CS fallback triggered.", (), ()),
    "radioNetwork:24": ("The UE is not available for PS service (e.g. during CS fallback without PS handover).", (), ()),
    "radioNetwork:26": ("A radio interface procedure failed.", ("security mode or RRC reconfiguration failed",), ()),
    "radioNetwork:13": ("The MME UE S1AP ID is unknown to the eNB.", ("context already released, or a race",), ("radioNetwork:14",)),
    "radioNetwork:14": ("The eNB UE S1AP ID is unknown to the MME.", (), ("radioNetwork:13",)),
    "radioNetwork:3": ("Release for an E-UTRAN generated reason.", (), ()),
    "radioNetwork:37": ("The QCI is not supported by the eNB.", ("QCI 1/5 bearer to an eNB without VoLTE",), ()),
    "nas:0": ("Normal release requested by NAS.", (), ()),
    "nas:1": ("Release after an authentication failure.", (), ("EMM 3",)),
    "nas:2": ("Release after detach.", (), ()),
    "transport:0": ("Transport resource unavailable.", ("S1-U path failure",), ()),
    "misc:0": ("Control processing overload.", (), ()),
    "misc:3": ("O&M intervention.", (), ()),
    "misc:5": ("Unknown PLMN.", (), ()),
    "protocol:0": ("Transfer syntax error: the message could not be decoded.", (), ()),
}
NGAP: dict[str, Entry] = {
    "radioNetwork:20": ("User inactivity: the gNB released an idle UE (normal).", (), ()),
    "radioNetwork:21": ("The radio connection with the UE was lost.", (), ()),
    "radioNetwork:36": ("IMS voice EPS fallback or RAT fallback triggered.", ("VoNR not supported: the call moves to LTE",), ()),
    "radioNetwork:39": ("The slice is not supported.", (), ()),
    "nas:0": ("Normal release requested by NAS.", (), ()),
    "nas:2": ("Release after deregistration.", (), ()),
    "misc:0": ("Control processing overload.", (), ()),
}

# ----------------------------------------------------------------- Diameter
DIAMETER_BASE: dict[int, Entry] = {
    1001: ("Multi-round authentication: another request is expected.", (), ()),
    2001: ("Success.", (), ()),
    2002: ("Limited success: the request was handled but more action is needed.", (), ()),
    3001: ("The command is not supported by the peer.", ("wrong application for this peer",), ("3007",)),
    3002: {"meaning": "The request could not be delivered to the destination (a Diameter agent says so).",
           "typical": ("no route in the DRA for the Destination-Realm or host", "the next peer is down",
                       "the HSS or PCRF behind the DRA is unreachable"),
           "related": ("3003", "3010"),
           "next": ("diameter_transactions(path): Origin-Host of the answer is the agent that failed",)},
    3003: ("The realm is not served by this peer.", ("Destination-Realm typo or missing roaming route",), ("3002",)),
    3004: ("The peer is too busy; try another.", ("overload",), ()),
    3005: ("A routing loop was detected (Route-Record).", ("DRA routing tables pointing at each other",), ()),
    3006: ("Redirect indication from a redirect agent.", (), ()),
    3007: ("The application is not supported by the peer.", ("CER/CEA did not advertise it",), ("5010",)),
    3010: ("The peer is unknown (no CER/CEA done).", (), ()),
    4001: ("Authentication rejected.", ("wrong credentials in an AAA or credit-control exchange",), ()),
    4010: ("End user service denied (credit control).", ("OCS refused the service",), ("4012",)),
    4011: ("Credit control not applicable for this service.", (), ()),
    4012: ("Credit limit reached.", ("no balance",), ("4010",)),
    5001: ("A mandatory AVP is not supported (the M bit set on an unknown AVP).", ("vendor AVP with M bit",), ("5008",)),
    5002: ("The Session-Id is unknown.", ("session lost after a restart", "request after a session ended"), ()),
    5003: ("Authorisation rejected.", (), ()),
    5004: ("An AVP has an invalid value; Failed-AVP names it.", (), ("5005",)),
    5005: ("A required AVP is missing; Failed-AVP names it.", ("interworking between releases",), ("5004",)),
    5006: ("A resource limit was exceeded.", (), ()),
    5007: ("The AVPs contradict each other.", (), ()),
    5008: ("An AVP is not allowed in this message.", (), ("5001",)),
    5009: ("An AVP occurs too many times.", (), ()),
    5010: ("No common application between the peers (CEA).", (), ("3007",)),
    5012: ("Unable to comply: a generic failure.", ("backend error at the server",), ()),
    5030: ("The user is unknown (credit control, RFC 4006).", ("subscriber not provisioned on the OCS",), ()),
}

DIAMETER_EXPERIMENTAL: dict[int, Entry] = {
    2001: ("Cx: first registration of this user to an S-CSCF (MAA/SAA).", (), ("2002",)),
    2002: ("Cx: subsequent registration (the user is already registered).", (), ("2001",)),
    4100: ("Sh: the requested user data is temporarily not available.", (), ()),
    4181: ("S6a: the HSS has no authentication vectors for the user right now.",
           ("AuC or HSS backend problem", "authentication data not provisioned"), ("5001",)),
    4182: ("S6a: the subscriber has a CAMEL subscription the MME cannot handle.", (), ()),
    4201: ("The user is absent.", (), ()),
    5001: {"meaning": "The user is unknown to the HSS.",
           "typical": ("IMSI or IMPI not provisioned", "the request reached the wrong HSS"),
           "related": ("5420", "EMM 2"),
           "by_application": {
               "s6a": "S6a (TS 29.272 7.4.3.1): the IMSI is not provisioned in the HSS; the MME rejects with EMM 8 or 2.",
               "cx": "Cx (TS 29.229 6.2.2.1): the IMS identity is unknown to the HSS; the I-CSCF answers 403 or 404.",
               "sh": "Sh (TS 29.329): the user identity is unknown to the HSS."}},
    5002: ("Cx: the public and private identities do not belong to the same user.", (), ()),
    5003: ("Cx: the identity is not registered.", (), ()),
    5004: {"meaning": "Roaming is not allowed.",
           "typical": ("no roaming agreement with the visited network", "Operator Determined Barring of roaming"),
           "related": ("5420", "EMM 11", "EMM 14"),
           "by_application": {
               "s6a": ("S6a (TS 29.272 7.4.3.3): the visited PLMN is not allowed; an Error-Diagnostic AVP may say "
                       "ODB_ALL_APN, ODB_HPLMN_APN or ODB_VPLMN_APN. The MME usually rejects with EMM 11, 13 or 14."),
               "cx": "Cx (TS 29.229 6.2.2.3): the user may not roam in the visited IMS network (P-CSCF network)."}},
    5005: ("Cx: the identity is already registered to another S-CSCF.", (), ()),
    5006: ("Cx: the authentication scheme is not supported.", (), ()),
    5100: ("Sh: the user data is not recognised.", (), ()),
    5101: ("Sh: the operation is not allowed.", (), ()),
    5106: ("Sh: the subscription data is absent.", (), ()),
    5140: ("Gx: the PCRF rejected the initial parameters (CCR-I).", ("unknown APN or user at the PCRF",), ("5065",)),
    5142: ("Gx: a PCC rule failed (see Charging-Rule-Report).", ("rule not installable on the PCEF",), ("5143",)),
    5143: ("Gx: the bearer is not authorised.", (), ()),
    5065: ("Rx: no IP-CAN session exists for the UE address the AF named.",
           ("the PCRF has no Gx session for the UE IP (PCRF binding wrong, or the PDN connection is gone)",),
           ("5140",)),
    5061: ("Rx: the service information is invalid.", ("SDP-derived media component rejected",), ()),
    5063: ("Rx: the requested service is not authorised.", (), ()),
    5420: {"meaning": "S6a: the user has no EPS subscription.",
           "typical": ("the subscriber is provisioned for 2G/3G only", "EPS subscription data missing on the HSS"),
           "related": ("5004", "5001", "EMM 15", "EMM 7")},
    5421: ("S6a: the RAT type is not allowed (Access-Restriction-Data).", ("LTE barred for the subscriber",), ("GTPv2 82",)),
    5422: ("S6a/S13: the equipment (IMEI) is unknown to the EIR.", (), ("EMM 5",)),
    5423: ("S6a: the serving node in a NOR/IDR is unknown.", (), ()),
    5450: ("SWx/S6b: no non-3GPP subscription.", (), ()),
    5451: ("S6b/SWm: no subscription for the requested APN.", (), ("GTPv2 93",)),
    5452: ("The RAT type is not allowed for non-3GPP access.", (), ()),
}

# ----------------------------------------------------------------- Q.850 (ISUP, CAMEL, SIP Reason)
Q850: dict[int, Entry] = {
    1: ("The number is not assigned.", ("dialled number does not exist", "number portability data wrong"), ("SIP 404",)),
    3: ("No route to the destination.", ("routing table gap",), ("SIP 404",)),
    16: ("Normal call clearing: one party hung up.", (), ("31",)),
    17: ("The called user is busy.", (), ("SIP 486",)),
    18: ("No user responding (no alerting before the timer expired).", ("UE unreachable", "paging failed"), ("19", "SIP 408")),
    19: ("No answer from the user after alerting.", (), ("18", "SIP 480")),
    20: ("The subscriber is absent (detached or unreachable).", (), ("SIP 480",)),
    21: ("The call was rejected.", ("call barring, the user declined",), ("SIP 603", "SIP 403")),
    22: ("The number changed.", (), ("SIP 410",)),
    27: ("The destination is out of order.", ("access link down at the far end",), ("SIP 502",)),
    28: ("Invalid number format (incomplete number).", (), ("SIP 484",)),
    29: ("The facility was rejected.", (), ("SIP 501",)),
    31: ("Normal, unspecified.", (), ("16",)),
    34: ("No circuit or channel available.", ("trunk group full",), ("SIP 503",)),
    38: ("The network is out of order.", (), ("SIP 503",)),
    41: ("Temporary failure.", (), ("SIP 503",)),
    42: ("Switching equipment congestion.", (), ("SIP 503",)),
    44: ("The requested circuit or channel is not available.", (), ()),
    47: ("Resources unavailable, unspecified.", (), ()),
    50: ("The requested facility is not subscribed.", (), ()),
    55: ("Incoming calls barred.", (), ("SIP 403",)),
    57: ("The bearer capability is not authorised.", (), ()),
    58: ("The bearer capability is not presently available.", (), ("SIP 488",)),
    63: ("Service or option not available.", (), ()),
    65: ("The bearer capability is not implemented.", ("codec or bearer mismatch at interworking",), ("SIP 488",)),
    79: ("Service or option not implemented.", (), ("SIP 501",)),
    88: ("Incompatible destination.", ("codec or bearer mismatch",), ("SIP 488",)),
    102: ("Recovery on timer expiry.", ("a protocol timer expired at the interworking node",), ("SIP 504",)),
    111: ("Protocol error, unspecified.", (), ()),
    127: ("Interworking, unspecified: the cause came from a network that did not give one.", (), ("SIP 500",)),
}

# ----------------------------------------------------------------- SIP (no tshark value table: names here)
SIP: dict[int, Entry] = {
    100: {"name": "Trying", "meaning": "The next hop received the request and is working on it.", "typical": ()},
    180: {"name": "Ringing", "meaning": "The called UE is alerting.", "typical": ()},
    181: {"name": "Call Is Being Forwarded", "meaning": "The call is being forwarded.", "typical": ()},
    183: {"name": "Session Progress", "meaning": "Early media or preconditions; ringback may come from the network.",
          "typical": ()},
    200: {"name": "OK", "meaning": "Success.", "typical": ()},
    202: {"name": "Accepted", "meaning": "Accepted for processing (MESSAGE, REFER, SUBSCRIBE); the result comes later.",
          "typical": ()},
    301: {"name": "Moved Permanently", "meaning": "The user moved; Contact gives the new address.", "typical": ()},
    302: {"name": "Moved Temporarily", "meaning": "Redirect to the Contact given.", "typical": ()},
    400: {"name": "Bad Request", "meaning": "The request was malformed.", "typical": ("syntax error, missing header",)},
    401: {"name": "Unauthorized", "meaning": "Authentication required by a UAS or registrar.",
          "typical": ("first REGISTER of an AKA or digest exchange (normal)",),
          "by_message": {"REGISTER": "Normal on the first REGISTER: the challenge (AKA nonce or digest). A second 401 "
                                     "after the authenticated REGISTER means the credentials or the AKA response failed."}},
    403: {"name": "Forbidden", "meaning": "The server understood the request and refuses it.",
          "typical": ("barring", "not authorised for this service"),
          "by_message": {"REGISTER": "IMS registration refused: the HSS answered Cx with an error (e.g. 5001 user "
                                     "unknown, 5004 roaming not allowed) or the IMPI/IMPU pair does not match.",
                         "INVITE": "Call refused by policy: barring, not provisioned for voice, or an AS rejected it."},
          "related": ("Diameter 5001", "Diameter 5004", "Q.850 21")},
    404: {"name": "Not Found", "meaning": "The user does not exist at the domain.",
          "typical": ("number not routable", "IMPU not provisioned"), "related": ("Q.850 1", "Q.850 3")},
    405: {"name": "Method Not Allowed", "meaning": "The method is not allowed for this resource.", "typical": ()},
    407: {"name": "Proxy Authentication Required", "meaning": "A proxy requires authentication.", "typical": ()},
    408: {"name": "Request Timeout", "meaning": "No final response in time.",
          "typical": ("UE unreachable or paging failed", "a downstream hop did not answer"), "related": ("Q.850 18",)},
    410: {"name": "Gone", "meaning": "The user existed but is no longer available.", "typical": ()},
    415: {"name": "Unsupported Media Type", "meaning": "The body type is not supported.", "typical": ()},
    420: {"name": "Bad Extension", "meaning": "A Require option tag is not supported.", "typical": ("precondition or 100rel",)},
    421: {"name": "Extension Required", "meaning": "The server needs an extension the request did not list.", "typical": ()},
    423: {"name": "Interval Too Brief", "meaning": "The requested expiry is too short (Min-Expires says the minimum).",
          "typical": ()},
    480: {"name": "Temporarily Unavailable", "meaning": "The callee is not reachable right now.",
          "typical": ("UE not registered", "UE detached or out of coverage"), "related": ("Q.850 20", "Q.850 19")},
    481: {"name": "Call/Transaction Does Not Exist", "meaning": "No matching dialog or transaction.",
          "typical": ("BYE or re-INVITE after the far side already ended the call",), "related": ()},
    482: {"name": "Loop Detected", "meaning": "The request looped.", "typical": ()},
    483: {"name": "Too Many Hops", "meaning": "Max-Forwards reached zero.", "typical": ("routing loop",)},
    484: {"name": "Address Incomplete", "meaning": "The number is incomplete.", "typical": (), "related": ("Q.850 28",)},
    486: {"name": "Busy Here", "meaning": "The callee is busy.", "typical": (), "related": ("Q.850 17",)},
    487: {"name": "Request Terminated", "meaning": "The INVITE was cancelled (CANCEL) before an answer.",
          "typical": ("the caller hung up while ringing (normal)",)},
    488: {"name": "Not Acceptable Here", "meaning": "The session description is not acceptable.",
          "typical": ("no common codec", "SRTP or transport mismatch", "UE without +g.3gpp.smsip refused a MESSAGE"),
          "related": ("Q.850 65", "Q.850 88"),
          "next": ("media_path_check(path, call_id)", "sip_call_detail(path, call_id)")},
    489: {"name": "Bad Event", "meaning": "The event package is not supported.", "typical": ()},
    491: {"name": "Request Pending", "meaning": "Glare: another request on the same dialog is pending.", "typical": ()},
    500: {"name": "Server Internal Error", "meaning": "The server failed.", "typical": (), "related": ("Q.850 127",)},
    501: {"name": "Not Implemented", "meaning": "The method is not implemented.", "typical": ()},
    502: {"name": "Bad Gateway", "meaning": "A downstream server gave an invalid response.", "typical": ()},
    503: {"name": "Service Unavailable", "meaning": "The server is overloaded or down; Retry-After may say when to retry.",
          "typical": ("overload", "no route or trunk available"), "related": ("Q.850 34", "Q.850 41")},
    504: {"name": "Server Time-out", "meaning": "A downstream server did not answer in time.",
          "typical": ("HSS (Cx) or AS timeout behind an S-CSCF",), "related": ("Q.850 102",)},
    580: {"name": "Precondition Failure", "meaning": "The QoS precondition could not be met.",
          "typical": ("dedicated bearer for voice not established (Rx/Gx)",)},
    600: {"name": "Busy Everywhere", "meaning": "The callee is busy everywhere.", "typical": ()},
    603: {"name": "Decline", "meaning": "The callee declined the call.", "typical": (), "related": ("Q.850 21",)},
    604: {"name": "Does Not Exist Anywhere", "meaning": "The user does not exist anywhere.", "typical": ()},
    606: {"name": "Not Acceptable", "meaning": "The session is not acceptable anywhere.", "typical": ()},
}

# ----------------------------------------------------------------- MAP errors (TS 29.002 17.6.6; names here)
MAP: dict[int, Entry] = {
    1: {"name": "unknownSubscriber", "meaning": "The HLR does not know the IMSI or MSISDN.",
        "typical": ("not provisioned", "number ported out"), "related": ("Diameter 5001",)},
    5: {"name": "unidentifiedSubscriber", "meaning": "The VLR or SGSN does not know the subscriber.", "typical": ()},
    6: {"name": "absentSubscriberSM", "meaning": "The subscriber is absent for SMS (detached, unreachable).",
        "typical": ("UE off or out of coverage",), "related": ("27", "RP 28")},
    8: {"name": "roamingNotAllowed", "meaning": "The subscriber may not roam in this network.",
        "typical": ("no agreement, ODB, or regional restriction",), "related": ("Diameter 5004",)},
    9: {"name": "illegalSubscriber", "meaning": "Authentication failed: the subscriber is illegal.", "typical": ()},
    11: {"name": "teleserviceNotProvisioned", "meaning": "The teleservice (e.g. SMS) is not provisioned.", "typical": ()},
    12: {"name": "illegalEquipment", "meaning": "The IMEI is blacklisted.", "typical": ()},
    13: {"name": "callBarred", "meaning": "Barred by the subscription or ODB.", "typical": ()},
    21: {"name": "facilityNotSupported", "meaning": "The facility is not supported by the network.", "typical": ()},
    27: {"name": "absentSubscriber", "meaning": "The subscriber is absent (detached or purged).", "typical": (),
         "related": ("6",)},
    31: {"name": "subscriberBusyForMT-SMS", "meaning": "The subscriber is busy for MT SMS.", "typical": ()},
    32: {"name": "sm-DeliveryFailure", "meaning": "SMS delivery failed; the cause is inside (memory full, error in MS).",
         "typical": ("memory capacity exceeded", "equipment protocol error"), "related": ("RP 22",)},
    33: {"name": "messageWaitingListFull", "meaning": "The HLR's message waiting list is full.", "typical": ()},
    34: {"name": "systemFailure", "meaning": "Generic failure in the network entity.", "typical": ()},
    35: {"name": "dataMissing", "meaning": "A parameter needed is missing.", "typical": ()},
    36: {"name": "unexpectedDataValue", "meaning": "A parameter has an unexpected value.", "typical": ()},
    51: {"name": "resourceLimitation", "meaning": "Resource limitation (overload).", "typical": ()},
}

# ----------------------------------------------------------------- SS7 transport
TCAP_ABORT: dict[int, Entry] = {
    0: ("The message type is not recognised.", (), ()),
    1: ("The transaction ID is not recognised: the dialogue is unknown at the receiver.",
        ("the far end timed out the dialogue", "a TC-CONTINUE reached a different node"), ()),
    2: ("The transaction portion is badly formatted.", (), ()),
    3: ("The transaction portion is incorrect.", (), ()),
    4: ("Resource limitation at the far end.", ("overload",), ()),
}
SCCP_RETURN: dict[int, Entry] = {
    0: ("No translation for an address of such nature.", ("GT translation type or nature not configured",), ("1",)),
    1: ("No translation for this specific address: the global title cannot be routed.",
        ("missing GT range on the STP (new partner, new number range)",), ("0",)),
    2: ("Subsystem congestion.", (), ("3",)),
    3: ("Subsystem failure: the SSN at the destination is down.", ("HLR/MSC application down",), ("2",)),
    4: ("Unequipped user: the SSN does not exist at the destination.", ("wrong SSN in the called party",), ()),
    5: ("MTP failure: the destination point code is unreachable.", ("linkset down",), ()),
    6: ("Network congestion.", (), ()),
    7: ("Unqualified.", (), ()),
    8: ("Error in message transport.", (), ()),
    11: ("SCCP failure.", (), ()),
    12: ("Hop counter violation: a GT routing loop.", ("STPs routing a GT range at each other",), ()),
}
SGSAP: dict[int, Entry] = {
    1: ("IMSI detached for EPS services.", (), ()),
    2: ("IMSI detached for EPS and non-EPS services.", (), ()),
    3: ("The MSC/VLR does not know the IMSI.", ("SGs location update not done or lost after a VLR restart",), ()),
    4: ("IMSI detached for non-EPS services.", (), ()),
    5: ("IMSI implicitly detached for non-EPS services.", (), ()),
    6: ("The UE is unreachable.", (), ("14",)),
    13: ("The user rejected the CS fallback call.", (), ()),
    14: ("The UE is temporarily unreachable.", (), ("6",)),
}

# ----------------------------------------------------------------- SMS relay and transfer layers
RP: dict[int, Entry] = {
    1: ("Unassigned number.", (), ("Q.850 1",)),
    8: ("Operator determined barring.", (), ()),
    10: ("Call barred.", (), ()),
    21: ("The short message transfer was rejected.", ("SMSC or UE policy",), ()),
    22: ("Memory capacity exceeded at the UE: the HLR sets MWD and alerts the SMSC later.", ("UE storage full",),
         ("MAP 32",)),
    27: ("The destination is out of order.", (), ()),
    28: ("Unidentified subscriber.", (), ("MAP 5",)),
    29: ("Facility rejected.", (), ()),
    30: ("Unknown subscriber.", (), ("MAP 1",)),
    38: ("The network is out of order.", (), ()),
    41: ("Temporary failure.", (), ()),
    42: ("Congestion.", (), ()),
    47: ("Resources unavailable.", (), ()),
    50: ("The requested facility is not subscribed.", (), ()),
    69: ("The requested facility is not implemented.", (), ()),
    81: ("Invalid short message transfer reference value.", ("RP-MR mismatch between RP-DATA and the RP-ACK/ERROR",), ()),
    95: ("Semantically incorrect message.", (), ()),
    96: ("Invalid mandatory information.", (), ()),
    97: ("Message type non-existent or not implemented.", (), ()),
    98: ("Message not compatible with the short message protocol state.", (), ()),
    99: ("Information element non-existent or not implemented.", (), ()),
    111: ("Protocol error, unspecified.", (), ()),
    127: ("Interworking, unspecified.", (), ()),
}

CP: dict[int, Entry] = {
    17: {"name": "Network failure", "meaning": "Network failure on the CP layer.", "typical": ()},
    22: {"name": "Congestion", "meaning": "Congestion.", "typical": ()},
    81: {"name": "Invalid Transaction Identifier value", "meaning": "The TI is not valid.", "typical": ()},
    95: {"name": "Semantically incorrect message", "meaning": "Semantically incorrect message.", "typical": ()},
    96: {"name": "Invalid mandatory information", "meaning": "Invalid mandatory information.", "typical": ()},
    97: {"name": "Message type non-existent or not implemented", "meaning": "Unknown message type.", "typical": ()},
    98: {"name": "Message not compatible with the short message protocol state",
         "meaning": "The CP message does not fit the state.", "typical": ()},
    99: {"name": "Information element non-existent or not implemented", "meaning": "Unknown IE.", "typical": ()},
    111: {"name": "Protocol error, unspecified", "meaning": "Protocol error.", "typical": ()},
}

_TP = "TS 23.040 9.2.3.15"
TP_STATUS: dict[int, Entry] = {
    0x00: {"name": "Short message received by the SME", "meaning": "Delivered.", "typical": ()},
    0x01: {"name": "Forwarded by the SC to the SME but delivery not confirmed", "meaning": "Forwarded, unconfirmed.", "typical": ()},
    0x02: {"name": "Short message replaced by the SC", "meaning": "Replaced.", "typical": ()},
    0x20: {"name": "Congestion (temporary, SC still trying)", "meaning": "Temporary error; the SC keeps trying.", "typical": ()},
    0x21: {"name": "SME busy (temporary, SC still trying)", "meaning": "Temporary error; the SC keeps trying.", "typical": ()},
    0x22: {"name": "No response from SME (temporary, SC still trying)", "meaning": "Temporary error; the SC keeps trying.",
           "typical": ("UE absent",)},
    0x23: {"name": "Service rejected (temporary, SC still trying)", "meaning": "Temporary error; the SC keeps trying.", "typical": ()},
    0x24: {"name": "Quality of service not available (temporary, SC still trying)", "meaning": "Temporary error.", "typical": ()},
    0x25: {"name": "Error in SME (temporary, SC still trying)", "meaning": "Temporary error; the SC keeps trying.", "typical": ()},
    0x40: {"name": "Remote procedure error (permanent)", "meaning": "Permanent error; the SC stops.", "typical": ()},
    0x41: {"name": "Incompatible destination (permanent)", "meaning": "Permanent error.", "typical": ()},
    0x42: {"name": "Connection rejected by SME (permanent)", "meaning": "Permanent error.", "typical": ()},
    0x43: {"name": "Not obtainable (permanent)", "meaning": "Permanent error.", "typical": ()},
    0x44: {"name": "Quality of service not available (permanent)", "meaning": "Permanent error.", "typical": ()},
    0x45: {"name": "No interworking available (permanent)", "meaning": "Permanent error.", "typical": ()},
    0x46: {"name": "SM validity period expired (permanent)", "meaning": "The SC gave up when the validity period ended.",
           "typical": ("UE absent for longer than the validity period",)},
    0x47: {"name": "SM deleted by originating SME (permanent)", "meaning": "Deleted by the sender.", "typical": ()},
    0x48: {"name": "SM deleted by SC administration (permanent)", "meaning": "Deleted by the SC operator.", "typical": ()},
    0x49: {"name": "SM does not exist (permanent)", "meaning": "The SC has no such message.", "typical": ()},
    0x60: {"name": "Congestion (temporary, SC no longer trying)", "meaning": "The SC stopped trying.", "typical": ()},
    0x61: {"name": "SME busy (temporary, SC no longer trying)", "meaning": "The SC stopped trying.", "typical": ()},
    0x62: {"name": "No response from SME (temporary, SC no longer trying)", "meaning": "The SC stopped trying.", "typical": ()},
    0x63: {"name": "Service rejected (temporary, SC no longer trying)", "meaning": "The SC stopped trying.", "typical": ()},
    0x64: {"name": "Quality of service not available (temporary, SC no longer trying)", "meaning": "The SC stopped trying.",
           "typical": ()},
    0x65: {"name": "Error in SME (temporary, SC no longer trying)", "meaning": "The SC stopped trying.", "typical": ()},
}

# ----------------------------------------------------------------- 5G SBI ProblemDetails causes (string codes)
HTTP_SBI: dict[str, Entry] = {
    "USER_NOT_FOUND": {"meaning": "The UDM/UDR or AUSF does not know the SUPI/GPSI.", "typical": ("not provisioned",),
                       "ref": "TS 29.503 6.1.7.3 / TS 29.509", "related": ("Diameter 5001",)},
    "DATA_NOT_FOUND": {"meaning": "The requested subscription data does not exist.", "typical": (), "ref": "TS 29.503 6.1.7.3"},
    "CONTEXT_NOT_FOUND": {"meaning": "The NF has no context for the resource named.",
                          "typical": ("context lost after a restart",), "ref": "TS 29.502 / TS 29.518"},
    "SERVING_NETWORK_NOT_AUTHORIZED": {"meaning": "The home network does not authorise the serving network.",
                                       "typical": ("no roaming agreement",), "ref": "TS 29.509 6.1.7.3",
                                       "related": ("5GMM 73",)},
    "AUTHENTICATION_REJECTED": {"meaning": "Authentication was rejected.", "typical": (), "ref": "TS 29.509 6.1.7.3"},
    "DNN_NOT_SUPPORTED": {"meaning": "The DNN is not supported by the SMF.", "typical": (), "ref": "TS 29.502 6.1.7.3",
                          "related": ("5GSM 27",)},
    "SNSSAI_DENIED": {"meaning": "The S-NSSAI is not allowed for the UE.", "typical": (), "ref": "TS 29.502 / TS 29.531"},
    "DNN_DENIED": {"meaning": "The DNN is not allowed for the UE.", "typical": (), "ref": "TS 29.502 6.1.7.3"},
    "PDUTYPE_DENIED": {"meaning": "The PDU session type is not allowed.", "typical": (), "ref": "TS 29.502 6.1.7.3"},
    "INSUFFICIENT_RESOURCES_SLICE": {"meaning": "No resources for the slice.", "typical": (), "ref": "TS 29.502 6.1.7.3"},
    "INSUFFICIENT_RESOURCES_SLICE_DNN": {"meaning": "No resources for the slice and DNN.", "typical": (),
                                         "ref": "TS 29.502 6.1.7.3"},
    "ROAMING_NOT_ALLOWED": {"meaning": "Roaming is not allowed for the UE.", "typical": (), "ref": "TS 29.503 6.1.7.3",
                            "related": ("Diameter 5004",)},
    "RAT_NOT_ALLOWED": {"meaning": "The RAT is not allowed.", "typical": (), "ref": "TS 29.503 6.1.7.3",
                        "related": ("Diameter 5421",)},
    "MANDATORY_IE_MISSING": {"meaning": "A mandatory IE is missing from the request body.", "typical": (),
                             "ref": "TS 29.500 5.2.7.2"},
    "MANDATORY_IE_INCORRECT": {"meaning": "A mandatory IE is wrong.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
    "INVALID_MSG_FORMAT": {"meaning": "The body could not be parsed.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
    "NF_CONGESTION": {"meaning": "The NF is congested.", "typical": ("overload",), "ref": "TS 29.500 5.2.7.2"},
    "INSUFFICIENT_RESOURCES": {"meaning": "Insufficient resources in the NF.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
    "SYSTEM_FAILURE": {"meaning": "Generic NF failure.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
    "TARGET_NF_NOT_REACHABLE": {"meaning": "An SCP or SEPP could not reach the target NF.", "typical": (),
                                "ref": "TS 29.500 5.2.7.2"},
    "NF_SERVICE_FAILOVER": {"meaning": "The NF service failed over.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
    "UNSPECIFIED_NF_FAILURE": {"meaning": "Unspecified failure in the NF.", "typical": (), "ref": "TS 29.500 5.2.7.2"},
}

# Codes tshark names that have no curated text yet. Each still comes back with tshark's
# name and ``explained: false``. Codes tshark marks reserved or spare are not listed.
UNEXPLAINED: dict[str, frozenset[Any]] = {}  # filled in below by _unexplained()


def _unexplained(spec: dict[str, str]) -> None:
    for key, text in spec.items():
        codes: set[Any] = set()
        for part in text.split():
            group, _, numbers = part.rpartition(":")
            low, _, high = numbers.partition("-")
            for code in range(int(low), int(high or low) + 1):
                codes.add(f"{group}:{code}" if group else code)
        UNEXPLAINED[key] = frozenset(codes)


_unexplained({
    "diameter": (
        "2003-2009 3008-3009 3011 4002-4003 4005-4008 4013-4014 4241 5011 5013-5018 5024-5025 "
        "5031-5048 5241 "
    ),
    "diameter_experimental": (
        "2003-2005 2021 4101 4121 4141-4144 4221-4226 4241 4261 5007-5012 5041-5045 5062 5064 "
        "5066-5068 5102-5105 5107-5108 5120-5123 5141 5144-5149 5401-5403 5453-5454 5470-5471 5490 "
        "5510-5515 5530-5535 5550-5558 5570 5590-5602 5610-5612 5630-5641 5650-5653 5670-5671 "
        "5690-5691 "
    ),
    "gtpv2": (
        "2-15 74-77 85-86 95 97-98 102 105-106 108-109 111-112 114-115 121 124 126-131 "
    ),
    "gtpv1": (
        "0-7 59-63 177 195-198 203 206-208 212-218 221 223-228 230-233 252-255 "
    ),
    "pfcp": (
        "2 68 70-71 76 78 82-89 "
    ),
    "nas_emm": (
        "23-24 26 31 36 39 78 97-101 "
    ),
    "nas_esm": (
        "35 41-45 47 49 56-61 81 95-101 111 113 "
    ),
    "nas_5gmm": (
        "5-6 20-21 23-24 26 28 36 43 67 69 71 74-82 90 92-101 111 "
    ),
    "nas_5gsm": (
        "32 34-35 37 41-47 57-59 61 68 81-86 95-101 111 "
    ),
    "s1ap": (
        "radioNetwork:0-2 radioNetwork:4-12 radioNetwork:15-19 radioNetwork:22 radioNetwork:25 "
        "radioNetwork:27-36 radioNetwork:38-44 transport:1 nas:3-6 protocol:1-6 misc:1-2 misc:4 "
    ),
    "ngap": (
        "radioNetwork:0-19 radioNetwork:22-35 radioNetwork:37-38 radioNetwork:40-58 transport:0-1 "
        "nas:1 nas:3-6 protocol:0-6 misc:1-5 "
    ),
    "q850": (
        "0 2 4-11 14 23-26 30 33 35 37 39-40 43 45-46 49 51-54 56 62 66-70 81-87 89-93 95-101 103 "
        "110 "
    ),
    "isup": (
        "0 2 4-9 14 23-26 30 33 39-40 43 46 49 53 56 62 66 69-70 81-87 90-91 95-101 103 110 "
    ),
    "camel_release": (
        "0 2 4-9 14 23-26 30 33 39-40 43 46 49 53 56 62 66 69-70 81-87 90-91 95-101 103 110 "
    ),
    "map": (
        "3 7 10 54 71 "
    ),
    "sccp_return": (
        "9-10 13-14 247-254 "
    ),
    "sgsap": (
        "0 7-12 "
    ),
})
