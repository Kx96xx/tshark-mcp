"""Media path check for one SIP call: the SDP-negotiated addresses, ports and codecs
against the RTP actually seen, to explain one-way or no audio and 488 responses."""

from __future__ import annotations

from typing import Any

from . import sdp as sdp_mod
from .rtp import ep


def _negotiation(sdps: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """(offer, answer, failure SDP) of the last completed exchange; the last offer when
    nothing answered it. A later re-INVITE (hold, new address) wins over the first one."""
    offer = answer = failure = None
    pending = None
    for e in sdps:
        if e["role"] == "offer":
            pending = e
        elif e["role"] == "answer" and pending is not None:
            offer, answer = pending, e
            pending = None
        elif e["role"] == "failure_response":
            failure = e
    if pending is not None and offer is None:
        offer = pending
    return offer, answer, failure


def _audio(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not entry:
        return None
    media = entry["sdp"]["media"]
    return next((m for m in media if m.get("media") == "audio"), media[0] if media else None)


def _side(entry: dict[str, Any], media: dict[str, Any]) -> dict[str, Any]:
    out = {"sdp_frame": entry["frame"], "message": entry["message"], "signalled_by": entry["src"],
           **sdp_mod.summary(media)}
    if media.get("address") and media.get("port"):
        out["media_endpoint"] = ep(media["address"], media["port"])
    return out


def _pts(stream: dict[str, Any]) -> set[int]:
    if stream.get("payload_types"):
        return {int(k) for k in stream["payload_types"]}
    return {stream["payload_type"]} if stream.get("payload_type") is not None else set()


def check(call_id: str, sdps: list[dict[str, Any]], streams: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare what the SDP negotiated with the RTP seen and list the issues found."""
    issues: list[dict[str, str]] = []

    def issue(kind: str, detail: str) -> None:
        issues.append({"kind": kind, "detail": detail})

    offer, answer, failure = _negotiation(sdps)
    o_media, a_media, f_media = _audio(offer), _audio(answer), _audio(failure)
    out: dict[str, Any] = {"call_id": call_id}
    if offer is None:
        issue("no_sdp", "no SDP offer for this call in the capture, so the negotiated media is unknown")
        out["issues"] = issues
        out["verdict"] = issues[0]["detail"]
        return out
    out["offer"] = _side(offer, o_media)
    if answer:
        out["answer"] = _side(answer, a_media)

    # Codecs: what the two sides can share explains a 488; an answer must pick from the offer.
    if o_media and a_media:
        common = sdp_mod.common_codecs(o_media, a_media)
        out["common_codecs"] = common
        if not common and sdp_mod.voice_codecs(a_media):
            issue("codec_mismatch", "the answer's codecs (" + ", ".join(sdp_mod.codec_label(c) for c in sdp_mod.voice_codecs(a_media))
                  + ") are not in the offer (" + ", ".join(sdp_mod.codec_label(c) for c in sdp_mod.voice_codecs(o_media)) + ")")
    elif o_media and f_media:
        common = sdp_mod.common_codecs(o_media, f_media)
        out["failure_sdp"] = _side(failure, f_media)
        out["common_codecs"] = common
        if not common:
            issue("codec_mismatch", f"{failure['message'].split()[0]}: no codec in common; the offer has "
                  + ", ".join(sdp_mod.codec_label(c) for c in sdp_mod.voice_codecs(o_media))
                  + f" and the {failure['message'].split()[0]} lists "
                  + ", ".join(sdp_mod.codec_label(c) for c in sdp_mod.voice_codecs(f_media)))
    elif o_media and answer is None:
        issue("no_answer", "the offer was never answered with SDP, so no media was negotiated")

    for role, media in (("offer", o_media), ("answer", a_media)):
        if not media:
            continue
        if media.get("port") == 0:
            issue("media_rejected", f"the {role} rejects the audio stream (port 0)")
        if media.get("direction") in ("sendonly", "recvonly", "inactive"):
            issue("media_direction", f"the {role} sets a={media['direction']} (hold or one-way by signalling)")
        if sdp_mod.is_private(media.get("address")):
            issue("private_sdp_address", f"the {role} advertises the private address {media['address']}; "
                  "it is reachable only inside its own network (normal for an IMS UE inside the operator's core, "
                  "a problem when the far end is outside it)")

    if not (o_media and a_media):
        out["issues"] = issues
        out["verdict"] = "; ".join(i["detail"] for i in issues) or "no media was negotiated"
        out["rtp_streams"] = len(streams)
        return out

    o_ep = (o_media.get("address"), o_media.get("port"))
    a_ep = (a_media.get("address"), a_media.get("port"))
    o_str, a_str = ep(*o_ep), ep(*a_ep)
    allowed = {c["pt"] for m in (o_media, a_media) for c in m.get("codecs", []) if isinstance(c["pt"], int)}

    directions = []
    for name, sender, receiver, sender_ep, receiver_ep in (
        ("offerer to answerer", "offerer", "answerer", o_str, a_str),
        ("answerer to offerer", "answerer", "offerer", a_str, o_str),
    ):
        to_receiver = [s for s in streams if s["dst"] == receiver_ep]
        from_sender = [s for s in streams if s["src"] == sender_ep and s["dst"] != receiver_ep]
        row: dict[str, Any] = {"direction": name, "expected": f"{sender_ep} > {receiver_ep}",
                               "streams": [{"ssrc": s["ssrc"], "src": s["src"], "dst": s["dst"], "packets": s["packets"],
                                            "codec": s.get("codec"), "first_frame": s.get("first_frame")}
                                           for s in to_receiver + from_sender]}
        if to_receiver:
            sources = sorted({s["src"] for s in to_receiver})
            if sources != [sender_ep]:
                row["status"] = "arrives from another source"
                issue("source_differs_from_sdp",
                      f"RTP to the {receiver} ({receiver_ep}) comes from {', '.join(sources)}, not from the {sender}'s SDP "
                      f"address {sender_ep}: a NAT or media relay rewrote it")
            else:
                row["status"] = "as negotiated"
            for s in to_receiver:
                bad = sorted(_pts(s) - allowed)
                if bad:
                    issue("payload_type_not_negotiated",
                          f"stream {s['ssrc']} to the {receiver} carries payload type(s) {', '.join(map(str, bad))} that neither SDP lists")
        elif from_sender:
            row["status"] = "sent elsewhere"
            issue("rtp_to_wrong_address",
                  f"the {sender} ({sender_ep}) sends RTP to {', '.join(sorted({s['dst'] for s in from_sender}))}, "
                  f"not to the {receiver}'s SDP address {receiver_ep}")
        else:
            row["status"] = "missing"
        directions.append(row)
    out["directions"] = directions

    missing = [d for d in directions if d["status"] == "missing"]
    if not streams:
        issue("no_rtp", "no RTP for this call in the capture: the capture point may not see the media path, "
              "the media may be encrypted or tunnelled, or it never flowed")
    elif missing:
        for d in missing:
            issue("one_way_media", f"no RTP seen {d['direction']} ({d['expected']}): one-way audio as captured")

    # NAT without latching: one side's real source differs from its private SDP address and
    # the far end still sends to the SDP address.
    for sender, receiver, sender_media, receiver_ep_str, sender_ep_str in (
        ("offerer", "answerer", o_media, a_str, o_str), ("answerer", "offerer", a_media, o_str, a_str),
    ):
        observed = sorted({s["src"] for s in streams if s["dst"] == receiver_ep_str and s["src"] != sender_ep_str})
        back_to_sdp = [s for s in streams if s["dst"] == sender_ep_str]
        if observed and back_to_sdp and sdp_mod.is_private(sender_media.get("address")):
            issue("nat_not_latched",
                  f"the {sender} advertises the private address {sender_ep_str} but its RTP comes from {', '.join(observed)}; "
                  f"the {receiver} keeps sending to the private address, which cannot cross the NAT: one-way audio "
                  "(fix with symmetric RTP / latching or a correct SDP address)")

    out["issues"] = issues
    out["rtp_streams"] = len(streams)
    if not issues:
        out["verdict"] = "media flows both ways between the negotiated addresses with negotiated payload types"
    else:
        order = ("codec_mismatch", "no_answer", "no_rtp", "nat_not_latched", "one_way_media", "rtp_to_wrong_address",
                 "source_differs_from_sdp", "media_rejected", "media_direction", "private_sdp_address",
                 "payload_type_not_negotiated", "no_sdp")
        first = min(issues, key=lambda i: order.index(i["kind"]) if i["kind"] in order else len(order))
        out["verdict"] = first["detail"]
    return out
