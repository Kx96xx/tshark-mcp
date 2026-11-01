from __future__ import annotations

from tshark_mcp.pairing import Message, pair_messages


def _msg(frame: int, t: float, req: bool, key, name="X", **fields) -> Message:
    return Message(frame=frame, time=t, src="a", dst="b", is_request=req, key=key, name=name, fields=fields)


def test_pairs_oldest_pending_request_first():
    msgs = [
        _msg(1, 0.0, True, "k"),
        _msg(2, 0.1, True, "k"),
        _msg(3, 0.2, False, "k"),
        _msg(4, 0.3, False, "k"),
    ]
    txs = pair_messages(msgs)
    assert [(t.request.frame, t.answer.frame) for t in txs] == [(1, 3), (2, 4)]
    assert txs[0].rtt_ms == 200.0


def test_unanswered_and_unmatched_are_both_reported():
    msgs = [_msg(1, 0.0, True, "k1"), _msg(2, 0.5, False, "k2")]
    txs = pair_messages(msgs)
    assert len(txs) == 2
    assert txs[0].unanswered is True and txs[0].answer is None
    assert txs[1].request is None and txs[1].answer.frame == 2 and txs[1].unanswered is False


def test_compatible_can_veto_a_match():
    msgs = [
        _msg(1, 0.0, True, "k", session="s1"),
        _msg(2, 0.1, True, "k", session="s2"),
        _msg(3, 0.2, False, "k", session="s2"),
    ]
    txs = pair_messages(msgs, compatible=lambda r, a: r.fields["session"] == a.fields["session"])
    by_req = {t.request.frame: t for t in txs if t.request}
    assert by_req[1].answer is None
    assert by_req[2].answer.frame == 3


def test_one_way_messages_are_not_unanswered():
    m = _msg(1, 0.0, True, "k")
    m.expects_answer = False
    txs = pair_messages([m])
    assert txs[0].unanswered is False


def test_out_of_order_input_is_sorted_by_time():
    msgs = [_msg(2, 1.0, False, "k"), _msg(1, 0.0, True, "k")]
    txs = pair_messages(msgs)
    assert len(txs) == 1 and txs[0].request.frame == 1 and txs[0].answer.frame == 2
