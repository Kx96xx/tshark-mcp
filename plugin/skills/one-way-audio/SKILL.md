---
name: one-way-audio
description: One-way or no audio on a SIP call in a capture. Use when a caller or callee hears nothing, or audio stops in one direction.
---

# One-way or no audio

Get the server's `one_way_audio` prompt (it takes `path` and optionally `call_id`) for the
full checklist, or:

1. `sip_dialogs(path)` to find the Call-ID of the call.
2. `media_path_check(path, call_id)`: negotiated media of each side against the RTP seen in
   each direction; the verdict names the missing direction.
3. `sip_call_detail(path, call_id)` for hold, re-INVITEs and who hung up.
4. `rtp_streams(path, call_id=...)` for loss and jitter per SSRC.

Answer with the direction that is missing, the addresses and ports, and the frames.
