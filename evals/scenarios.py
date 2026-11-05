"""The scenarios: one operator question each, over the synthetic captures of tests/pcapgen.py.

Facts are the ones the generator put in the capture (documentation addresses, the test PLMN
001/01, reserved numbers), so a check that fails means a tool stopped telling that story.
"""

from __future__ import annotations

from .harness import Check as C
from .harness import Scenario, Step

IMSI = "001010123456789"
IMSI_OTHER = "001010987654321"
IMSI_NO_EPS = "001010222333444"
IMS_LOOP = "001010000000102"
SMS_A = "001010000000201"

SCENARIOS: list[Scenario] = [
    Scenario(
        id="one_way_audio",
        question="On examples/sip_one_way_audio.pcap the caller hears nothing. Which direction of the media is missing?",
        steps=(
            Step("sip_dialogs", {"path": "{captures}/examples/sip_one_way_audio.pcap"},
                 (C("dialogs[0].call_id", "eq", "one-way-audio-1@ue.example"),)),
            Step("media_path_check", {"path": "{captures}/examples/sip_one_way_audio.pcap", "call_id": "{step0:dialogs[0].call_id}"},
                 (C("issues[*].kind", "eq", "one_way_media"),
                  C("verdict", "startswith", "no RTP seen answerer to offerer"),
                  C("directions[1].status", "eq", "missing"),
                  C("directions[1].expected", "eq", "192.0.2.70:30010 > 198.51.100.9:40010"))),
        ),
        answer=(r"192\.0\.2\.70", r"one[- ]way|missing"),
        reference_answer="One-way media: no RTP from the answerer 192.0.2.70:30010 to the offerer 198.51.100.9:40010; the other direction flows as negotiated (PCMA).",
    ),
    Scenario(
        id="codec_mismatch_488",
        question="A call in voice/voice_problems.pcap was rejected with 488. Why?",
        steps=(
            Step("sip_dialogs", {"path": "{captures}/voice/voice_problems.pcap", "columns": ["call_id", "final_status"]},
                 (C("dialogs[final_status=488].call_id", "eq", "voice-488-4@ue.example"),)),
            Step("media_path_check", {"path": "{captures}/voice/voice_problems.pcap", "call_id": "{step0:dialogs[final_status=488].call_id}"},
                 (C("issues[*].kind", "eq", "codec_mismatch"), C("common_codecs", "eq", []),
                  C("failure_sdp.codecs", "eq", ["AMR-WB/16000"]))),
        ),
        answer=(r"codec", r"AMR-WB"),
        reference_answer="488 because there is no codec in common: the offer has PCMU and PCMA, the 488 lists only AMR-WB/16000.",
    ),
    Scenario(
        id="unknown_eps_subscription",
        question="Why does the attach in examples/diameter_error_answer.pcap fail?",
        steps=(
            Step("diameter_transactions", {"path": "{captures}/examples/diameter_error_answer.pcap"},
                 (C("summary.failed", "eq", 1),
                  C("transactions[success=False].experimental_result_code", "eq", 5420),
                  C("transactions[success=False].result", "eq", "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"),
                  C("transactions[success=False].user_name", "eq", IMSI_NO_EPS))),
        ),
        answer=(r"5420", r"UNKNOWN_EPS_SUBSCRIPTION|unknown EPS subscription"),
        reference_answer=f"The HSS answered the ULR for {IMSI_NO_EPS} with Experimental-Result 5420 DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION.",
    ),
    Scenario(
        id="gtp_cause_78",
        question="Which Create Session in examples/gtpv2_create_session_rejected.pcap was rejected, and why?",
        steps=(
            Step("gtp_sessions", {"path": "{captures}/examples/gtpv2_create_session_rejected.pcap"},
                 (C("summary.failed", "eq", 1),
                  C("transactions[accepted=False].cause", "eq", 78),
                  C("transactions[accepted=False].cause_name", "eq", "Missing or unknown APN"),
                  C("transactions[accepted=False].apn", "eq", "internet.wrong.apn"),
                  C("transactions[accepted=False].imsi", "eq", IMSI_OTHER))),
        ),
        answer=(r"\b78\b", r"unknown APN", r"internet\.wrong\.apn"),
        reference_answer=f"The PGW rejected the Create Session for {IMSI_OTHER} with cause 78, Missing or unknown APN: it asked for internet.wrong.apn.",
    ),
    Scenario(
        id="unanswered_air",
        question="Did every Diameter request in diameter.pcap get an answer? Which one did not?",
        steps=(
            Step("diameter_transactions", {"path": "{captures}/diameter.pcap"},
                 (C("summary.unanswered", "eq", 1),
                  C("transactions[unanswered=True].request", "eq", "AIR"),
                  C("transactions[unanswered=True].request_frame", "eq", 5),
                  C("transactions[unanswered=True].user_name", "eq", IMSI))),
        ),
        answer=(r"AIR", r"frame 5\b"),
        forbidden=(r"every request (was|got) answered",),
        reference_answer=f"No: the AIR in frame 5 for {IMSI} has no answer in the file; the others were answered.",
    ),
    Scenario(
        id="cause_lookup_5001",
        question="What does Diameter Experimental-Result 5001 on S6a mean?",
        steps=(
            Step("cause_lookup", {"protocol": "diameter", "code": 5001, "application": "s6a"},
                 (C("name", "regex", "USER_UNKNOWN"),)),
        ),
        answer=(r"USER_UNKNOWN|user unknown",),
        reference_answer="5001 is DIAMETER_ERROR_USER_UNKNOWN: the HSS does not know the IMSI.",
        max_calls=2,
    ),
    Scenario(
        id="ims_challenge_loop",
        question=f"Why can {IMS_LOOP} not register on IMS (ims/ims_register.pcap)?",
        steps=(
            Step("ims_registration", {"path": "{captures}/ims/ims_register.pcap", "imsi": IMS_LOOP},
                 (C("registrations[0].verdict", "eq", "challenge-loop"),
                  C("registrations[0].counts.challenges", "eq", 3),
                  C("registrations[0].reasons[*]", "regex", "AUTS"))),
        ),
        answer=(r"challenge", r"AUTS|resynch|SQN"),
        reference_answer="A challenge loop: three REGISTERs got 401, two of them already carrying a response, and the UE sent AUTS, so its SQN is out of sync with the HSS.",
    ),
    Scenario(
        id="sms_rp_error",
        question=f"Was every SMS that {SMS_A} sent over IMS accepted (ims/ims_sms.pcap)?",
        steps=(
            Step("sms_over_ims", {"path": "{captures}/ims/ims_sms.pcap", "imsi": SMS_A},
                 (C("messages[call_id=mo2@ims.example.com].ack.rp_cause", "eq", 21),
                  C("messages[call_id=mo2@ims.example.com].ack.rp_cause_name", "eq", "Short message transfer rejected"),
                  C("messages[call_id=mo1@ims.example.com].verdict", "eq", "accepted"))),
        ),
        answer=(r"RP-ERROR|rp.cause", r"\b21\b"),
        reference_answer="No: the first was accepted with RP-ACK, the second got RP-ERROR cause 21, Short message transfer rejected.",
    ),
    Scenario(
        id="find_subscriber_files",
        question=f"Which capture files mention IMSI {IMSI_OTHER}?",
        steps=(
            Step("find_identifier", {"path": "{captures}", "identifier": IMSI_OTHER},
                 (C("kind", "eq", "subscriber"),
                  C("files[*].path", "regex", r"/diameter\.pcap$"),
                  C("files[*].path", "regex", r"/gtpv2\.pcap$"))),
        ),
        answer=(r"diameter\.pcap", r"gtpv2\.pcap"),
        reference_answer=f"{IMSI_OTHER} appears in diameter.pcap, gtpv2.pcap and the merged all.pcap.",
        max_calls=3,
    ),
    Scenario(
        id="trace_subscriber_failures",
        question=f"Everything that happened to {IMSI_OTHER} in all.pcap: where did it fail?",
        steps=(
            Step("trace_subscriber", {"path": "{captures}/all.pcap", "imsi": IMSI_OTHER},
                 (C("failures", "eq", 2),
                  C("timeline[protocol=diameter].result", "eq", "DIAMETER_ERROR_USER_UNKNOWN"),
                  C("timeline[protocol=gtpv2].result", "eq", "Missing or unknown APN"))),
        ),
        answer=(r"USER_UNKNOWN|user unknown", r"unknown APN"),
        reference_answer="Two failures: the AIR was answered DIAMETER_ERROR_USER_UNKNOWN and the Create Session was rejected with Missing or unknown APN.",
    ),
    Scenario(
        id="redaction_join",
        question=f"With identifiers redacted, trace {IMSI_OTHER} in all.pcap and then list its Diameter sessions by the token.",
        steps=(
            Step("trace_subscriber", {"path": "{captures}/all.pcap", "imsi": IMSI_OTHER, "redact": "ids"},
                 (C("identity.imsi", "regex", r"^imsi:[0-9a-f]{10}$"), C("redaction.complete", "eq", True))),
            Step("diameter_sessions", {"path": "{captures}/diameter.pcap", "imsi": "{step0:identity.imsi}", "redact": "ids"},
                 (C("count", "ge", 1),)),
        ),
        forbidden=(IMSI_OTHER,),
        reference_answer="The token imsi:<hex> from trace_subscriber finds the same subscriber's AIR session in diameter.pcap; no raw IMSI appears.",
    ),
    Scenario(
        id="truncated_page_not_absent",
        question="Did any call in voice/call_legs.pcap fail? Look at every call, not only the first page.",
        steps=(
            Step("call_legs", {"path": "{captures}/voice/call_legs.pcap", "output": "summary"},
                 (C("total_matched", "eq", 5), C("returned", "le", 3), C("summary.failed_calls", "eq", 2),
                  C("next_offset", "present"))),
            Step("call_legs", {"path": "{captures}/voice/call_legs.pcap", "offset": "{step0:next_offset}"},
                 (C("returned", "ge", 1),)),
        ),
        answer=(r"\b2\b|two",),
        forbidden=(r"no (call|other call) failed", r"only one call"),
        reference_answer="Yes: 2 of the 5 calls failed; the first page showed only part of them, so the rest were read with next_offset.",
    ),
    Scenario(
        id="wrong_dir_recovers",
        question="Summarise /etc/hosts as a capture, and if that is refused, summarise diameter.pcap instead.",
        steps=(
            Step("pcap_info", {"path": "/etc/hosts"}, (C("error.fix", "present"), C("error.allowed_dirs", "present")),
                 expect_error="path_not_allowed"),
            Step("pcap_info", {"path": "{captures}/diameter.pcap"}, (C("packets", "eq", 7),)),
        ),
        tools=frozenset({"pcap_info"}),
        answer=(r"outside|not allowed|refused|path_not_allowed", r"\b7\b"),
        reference_answer="/etc/hosts is outside the allowed directories (path_not_allowed); diameter.pcap holds 7 packets.",
    ),
    Scenario(
        id="call_kpis_worst_peer",
        question="Which carrier in voice/call_mix.pcap has the lower answer-seizure ratio?",
        steps=(
            Step("call_kpis", {"path": "{captures}/voice/call_mix.pcap", "group_by": "peer"},
                 (C("groups[peer=203.0.113.10].asr_pct", "eq", 40.0),
                  C("groups[peer=203.0.113.20].asr_pct", "eq", 50.0))),
        ),
        answer=(r"203\.0\.113\.10", r"40"),
        reference_answer="203.0.113.10: ASR 40 % (2 of 5 answered) against 50 % for 203.0.113.20.",
    ),
    Scenario(
        id="b2bua_status_rewrite",
        question="In voice/call_legs.pcap the caller got 503. Which hop failed, and who rewrote the status?",
        steps=(
            Step("call_legs", {"path": "{captures}/voice/call_legs.pcap", "limit": 1},
                 (C("calls[0].caller_status", "eq", 503),
                  C("calls[0].where_it_failed.status", "eq", 480),
                  C("calls[0].where_it_failed.responder", "eq", "203.0.113.10"),
                  C("calls[0].status_mapping[rewritten=True].element", "eq", "192.0.2.90"))),
        ),
        answer=(r"480", r"192\.0\.2\.90"),
        reference_answer="The carrier 203.0.113.10 answered 480 (Q.850 18); the SBC at 192.0.2.90 rewrote it to 503 (Q.850 34) towards the caller.",
    ),
    Scenario(
        id="dtmf_wrong_payload_type",
        question="Why are some DTMF digits lost in voice/voice_dtmf.pcap?",
        steps=(
            Step("dtmf_events", {"path": "{captures}/voice/voice_dtmf.pcap"},
                 (C("events[digit=#].payload_type", "eq", 101),
                  C("events[digit=#].issues[*]", "regex", "not the negotiated telephone-event type"),
                  C("events[digit=9].response", "eq", 415))),
        ),
        answer=(r"payload type|101", r"415"),
        reference_answer="The # digit went out with payload type 101, not the negotiated telephone-event type 100, and the SIP INFO digit 9 was rejected with 415.",
    ),
]
