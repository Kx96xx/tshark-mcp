"""Generic request/answer pairing.

Each protocol module turns packets into :class:`Message` objects with a
``key`` (for Diameter the Hop-by-Hop and End-to-End identifiers, for GTPv2 the
sequence number and peer pair, and so on). :func:`pair_messages` then walks the
messages in time order, matching every answer to the oldest pending request
with the same key, and reports requests that never got an answer.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Hashable, Iterable

from .fields import iso


@dataclass
class Message:
    frame: int
    time: float
    src: str
    dst: str
    is_request: bool
    key: Hashable
    name: str
    fields: dict[str, Any] = field(default_factory=dict)
    expects_answer: bool = True
    interface: int | None = None  # pcapng interface id the packet was captured on

    @property
    def peers(self) -> frozenset[str]:
        return frozenset((self.src, self.dst))


@dataclass
class Transaction:
    request: Message | None
    answer: Message | None

    @property
    def time(self) -> float:
        if self.request is not None:
            return self.request.time
        assert self.answer is not None
        return self.answer.time

    @property
    def rtt_ms(self) -> float | None:
        if self.request is None or self.answer is None:
            return None
        return round((self.answer.time - self.request.time) * 1000.0, 3)

    @property
    def unanswered(self) -> bool:
        return self.request is not None and self.answer is None and self.request.expects_answer


Compatible = Callable[[Message, Message], "bool | int"]


def pair_messages(messages: Iterable[Message], compatible: Compatible | None = None) -> list[Transaction]:
    """Pair requests with answers sharing the same ``key``.

    ``compatible`` can veto a candidate match (for example when both sides carry
    a Session-Id and they differ) or rank it: a false or zero result rejects
    the candidate, a higher integer is preferred over a lower one, and among
    equal ranks the oldest pending request wins. Unmatched answers are returned
    as transactions with ``request=None`` so nothing silently disappears.
    """
    ordered = sorted(messages, key=lambda m: (m.time, m.frame))
    pending: dict[Hashable, deque[Transaction]] = defaultdict(deque)
    transactions: list[Transaction] = []
    for msg in ordered:
        if msg.is_request:
            tx = Transaction(request=msg, answer=None)
            transactions.append(tx)
            pending[msg.key].append(tx)
            continue
        queue = pending.get(msg.key)
        matched = None
        best = 0
        if queue:
            for candidate in queue:
                rank = 1 if compatible is None else int(compatible(candidate.request, msg))  # type: ignore[arg-type]
                if rank > best:
                    matched, best = candidate, rank
        if matched is None:
            transactions.append(Transaction(request=None, answer=msg))
        else:
            matched.answer = msg
            queue.remove(matched)
    transactions.sort(key=lambda t: (t.time, (t.request or t.answer).frame))  # type: ignore[union-attr]
    return transactions


def base_row(tx: Transaction) -> dict[str, Any]:
    """Fields every paired transaction shares."""
    req, ans = tx.request, tx.answer
    anchor = req or ans
    assert anchor is not None
    row: dict[str, Any] = {
        "time": iso(anchor.time),
        "src": anchor.src,
        "dst": anchor.dst,
        "request_frame": req.frame if req else None,
        "answer_frame": ans.frame if ans else None,
        "rtt_ms": tx.rtt_ms,
    }
    if tx.unanswered:
        row["unanswered"] = True
    if req is None:
        row["unmatched_answer"] = True
    return row


# ------------------------------------------------------------ proxy chains
DUPLICATE_WINDOW_S = 0.05
CHAIN_WINDOW_S = 1.0
RELAY_MARGIN_S = 0.2  # how long after the answer on the next leg a relayed response is still expected
ANSWER_WINDOW_S = 2.0  # the longest a request's answer is still expected when nothing in the capture says sooner


Announced = Callable[[Message], "list[tuple[int, str | None]]"]


def session_identity(txs: list[Transaction], announced: Announced) -> Callable[[Message], Hashable | None]:
    """Name the session (IMSI and APN) of every request, for :func:`annotate_legs`.

    A request that carries an IMSI (Create Session, Create PDP Context) names its own
    session. The control-plane TEIDs it and its response announce (``announced``: the
    sender F-TEID or TEID-C with its address) are remembered for that session, on each
    leg of a proxy chain, since each leg has its own. A later request without an IMSI
    (Modify Bearer, Delete Session, Update or Delete PDP Context, ...) belongs to the
    session whose TEID it carries in its header, or whose TEID it announces again
    (a Delete Session Request repeats the sender F-TEID). The TEIDs it announces are
    then added to that session too (a new SGW after a relocation). When a TEID was
    announced by several sessions, the one announced on the address the request is sent
    to (or that it announces) is preferred, then the latest before the request.
    The result is ``(imsi, message type, APN)``, so legs of one procedure share it
    whether or not they carry the IMSI. A request of an unknown session (its Create is
    not in the capture) is linked to the requests with the same message, sequence number
    and header TEID, which a proxy that keeps both sends on its other leg; with none of
    them in a known session they share a key of their own; a request without a header
    TEID or sequence number gets ``None``.
    """
    known: dict[int, list[tuple[float, str | None, tuple[str, str]]]] = defaultdict(list)
    names: dict[int, Hashable | None] = {}

    def lookup(req: Message) -> tuple[str, str] | None:
        header = req.fields.get("teid")
        wanted: list[tuple[int, str | None]] = [(header, req.dst)] if header else []
        wanted += announced(req)
        for teid, addr in wanted:
            entries = known.get(teid)
            if not entries:
                continue
            same_addr = [e for e in entries if addr and e[1] == addr]
            pool = same_addr or entries
            before = [e for e in pool if e[0] <= req.time]
            return max(before or pool, key=lambda e: e[0])[2]
        return None

    ordered = sorted((tx for tx in txs if tx.request is not None), key=lambda t: (t.request.time, t.request.frame))  # type: ignore[union-attr]
    for tx in ordered:
        req = tx.request
        assert req is not None
        imsi = req.fields.get("imsi")
        session = (imsi, (req.fields.get("apn") or "").lower()) if imsi else lookup(req)
        names[id(req)] = None if session is None else (session[0], req.fields.get("message_type"), session[1])
        if session is None:
            continue
        for msg in (req, tx.answer):
            if msg is None:
                continue
            for teid, addr in announced(msg):
                known[teid].append((msg.time, addr, session))
    # A proxy that keeps both the sequence number and the header TEID (the session was
    # set up before the capture started, so no TEID is known): the legs share the
    # message, sequence number and TEID. They take the session of a leg that has one.
    relayed: dict[tuple, list[Message]] = defaultdict(list)
    for tx in ordered:
        req = tx.request
        assert req is not None
        if req.fields.get("teid") and req.fields.get("seq") is not None:
            relayed[(req.fields.get("message_type"), req.fields["seq"], req.fields["teid"])].append(req)
    for key, reqs in relayed.items():
        named = [names[id(r)] for r in reqs if names[id(r)] is not None]
        for r in reqs:
            if names[id(r)] is None:
                names[id(r)] = named[0] if named else ("relayed",) + key
    return lambda msg: names.get(id(msg))


CaptureEnd = Callable[[Message], "float | None"]


def annotate_legs(txs: list[Transaction], rows: list[dict[str, Any]], identity: Callable[[Message], Hashable | None],
                  capture_end: CaptureEnd | None = None) -> None:
    """Explain requests without a response on captures that hold several legs of one procedure.

    ``rows[i]`` is the row built from ``txs[i]``; rows are changed in place.

    - **Duplicates**: the same request (same peers, sequence key and name) seen again
      within 50 ms is one packet captured twice (two interfaces or a mirror), not a
      retransmission; it gets ``duplicate_of_frame`` instead of ``unanswered``.
    - **Proxy chains**: requests with the same ``identity`` (for GTP: the message and the
      session's IMSI and APN, see :func:`session_identity`) within one second of the first
      are legs of one procedure relayed through proxies. When at least one leg has no response, every leg of the chain gets
      ``chain`` (``leg`` k of ``legs`` in time order, how many legs were answered and on
      which frames); fully answered chains are left as they are. When some legs were answered, a leg without a
      response gets ``leg_without_response`` instead of ``unanswered``, with a note
      saying whether the answered leg is further along the chain (the response was not
      relayed back on this leg, or was not captured here) or before it. When no leg was
      answered every leg stays ``unanswered``: the procedure itself got no response.
    - **Capture end**: ``capture_end(request)`` gives the time of the last packet captured
      on the request's interface (or in the whole capture). A leg without a response whose
      response would only have come after that, gets ``near_capture_end`` instead of
      ``leg_without_response``: the capture on its side had stopped, so a missing
      response says nothing. The response relayed back is expected by the answer on the
      leg further along plus ``RELAY_MARGIN_S``; when only a leg before it was answered
      (the relaying node gave up and answered on its own), by that answer. It is only
      called when such a leg exists.
    """
    seen: dict[tuple, Message] = {}
    dup: set[int] = set()
    for i, tx in enumerate(txs):
        req = tx.request
        if req is None:
            continue
        k = (req.src, req.dst, req.key, req.name)
        first_copy = seen.get(k)
        if first_copy is not None and req.time - first_copy.time <= DUPLICATE_WINDOW_S and tx.answer is None:
            dup.add(i)
            rows[i].pop("unanswered", None)
            rows[i]["duplicate_of_frame"] = first_copy.frame
            rows[i]["note"] = "the same request captured twice (identical packet seen again), not a retransmission"
        else:
            seen[k] = req
    groups: dict[Hashable, list[list[int]]] = {}
    order = sorted((i for i, tx in enumerate(txs) if tx.request is not None and i not in dup),
                   key=lambda i: (txs[i].request.time, txs[i].request.frame))  # type: ignore[union-attr]
    for i in order:
        req = txs[i].request
        assert req is not None
        ident = identity(req)
        if ident is None:
            continue
        chains = groups.setdefault(ident, [])
        if chains and req.time - txs[chains[-1][0]].request.time <= CHAIN_WINDOW_S:  # type: ignore[union-attr]
            chains[-1].append(i)
        else:
            chains.append([i])
    for chains in groups.values():
        for chain in chains:
            answered = [i for i in chain if txs[i].answer is not None]
            if len(chain) < 2 or len(answered) == len(chain):
                continue  # a single request, or every leg answered: nothing to explain
            answer_frames = [txs[i].answer.frame for i in answered]  # type: ignore[union-attr]
            for pos, i in enumerate(chain):
                row = rows[i]
                row["chain"] = {"leg": pos + 1, "legs": len(chain), "answered_legs": len(answered),
                                **({"answered_on_frames": answer_frames} if answer_frames else {})}
                if txs[i].answer is not None or not answered or not row.get("unanswered"):
                    continue
                row.pop("unanswered", None)
                later = [j for j in answered if chain.index(j) > pos]
                j = later[0] if later else answered[-1]
                answer = txs[j].answer
                assert answer is not None
                expected = answer.time + RELAY_MARGIN_S if later else answer.time
                end = capture_end(txs[i].request) if capture_end is not None else None  # type: ignore[arg-type]
                if end is not None and end < expected:
                    row["near_capture_end"] = True
                    row["note"] = (f"no response on this leg, but the capture on its side stops at {iso(end)}, "
                                   f"before the response could be seen: leg {chain.index(j) + 1} was answered at "
                                   f"{iso(answer.time)} (frame {answer.frame}{_cause(rows[j])}). Not counted as a "
                                   "leg without response")
                    continue
                row["leg_without_response"] = True
                if later:
                    row["note"] = (f"no response on this leg, but leg {chain.index(j) + 1} further along the chain was "
                                   f"answered (frame {txs[j].answer.frame}{_cause(rows[j])}): the response was not "  # type: ignore[union-attr]
                                   "relayed back to this sender, or was not captured on this leg")
                else:
                    row["note"] = (f"no response on this leg; leg {chain.index(j) + 1} before it was answered (frame "
                                   f"{txs[j].answer.frame}{_cause(rows[j])}): the node that relayed this request answered "  # type: ignore[union-attr]
                                   "on its own (the next hop did not answer), or the response on this leg was not captured")


def near_capture_end(request: Message | None, capture_end: CaptureEnd | None,
                     window: float = ANSWER_WINDOW_S) -> float | None:
    """The end of the capture on ``request``'s side when it stops less than ``window``
    seconds after the request (its answer could still have come after the capture
    stopped), else None. ``capture_end`` is the lookup :func:`annotate_legs` takes."""
    if request is None or capture_end is None:
        return None
    end = capture_end(request)
    if end is None or end >= request.time + window:
        return None
    return end


def answer_window(slowest_s: float | None, cap: float = ANSWER_WINDOW_S) -> float:
    """How long after a request its answer is still expected: the slowest answer of the
    same kind seen in the capture plus ``RELAY_MARGIN_S``, at most ``cap``; ``cap`` when
    none of that kind was answered."""
    if slowest_s is None:
        return cap
    return min(cap, slowest_s + RELAY_MARGIN_S)


def near_end_note(request_time: float, end: float, window: float, slowest_s: float | None = None) -> str:
    """The note on an unanswered request that the capture stopped too soon after."""
    why = (f"answers of this kind in the capture took at most {slowest_s * 1000.0:.0f} ms"
           if slowest_s is not None and window < ANSWER_WINDOW_S else f"answers are expected within {window:g} s")
    return (f"no response, but the capture on this side stops at {iso(end)}, "
            f"{(end - request_time) * 1000.0:.0f} ms after the request ({why}): the response may simply "
            "not have been captured")


def mark_unanswered_near_end(txs: list[Transaction], rows: list[dict[str, Any]], capture_end: CaptureEnd | None) -> None:
    """Flag ``near_capture_end`` (and a ``note``) on rows still ``unanswered`` whose capture
    stops before the answer was due. The answer is due within :func:`answer_window` of the
    request: the slowest answer to the same request name in ``txs`` plus
    ``RELAY_MARGIN_S``, at most ``ANSWER_WINDOW_S`` (2 s). ``unanswered`` stays: the
    response is missing either way, the flag says the capture cannot tell why. Run it
    after :func:`annotate_legs`; ``capture_end`` is only called for unanswered rows."""
    if capture_end is None or not any(r.get("unanswered") for r in rows):
        return
    slowest: dict[str, float] = {}
    for tx in txs:
        if tx.request is not None and tx.answer is not None:
            rtt = tx.answer.time - tx.request.time
            if rtt >= 0 and rtt > slowest.get(tx.request.name, -1.0):
                slowest[tx.request.name] = rtt
    for tx, row in zip(txs, rows):
        if not row.get("unanswered") or tx.request is None:
            continue
        seen = slowest.get(tx.request.name)
        window = answer_window(seen)
        end = near_capture_end(tx.request, capture_end, window)
        if end is not None:
            row["near_capture_end"] = True
            row["note"] = near_end_note(tx.request.time, end, window, seen)


def _cause(row: dict[str, Any]) -> str:
    cause, name = row.get("cause"), row.get("cause_name")
    if cause is None:
        return ""
    return f", cause {cause} {name}" if name else f", cause {cause}"
