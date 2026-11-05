---
name: subscriber-cannot-attach
description: A mobile subscriber cannot attach or gets no data bearer, seen in a capture with Diameter S6a and GTPv2-C. Use for attach failures, roaming failures and rejected Create Session.
---

# Subscriber cannot attach

Get the server's `subscriber_cannot_attach` prompt (`path`, `imsi`, `msisdn`, `home_plmn`)
for the full checklist, or:

1. `trace_subscriber(path, imsi=...)`: every message of the subscriber on one timeline.
2. `diameter_sessions(path, imsi=...)`, then `diameter_avps(path, imsi=..., detail="key")`
   behind a failing result code.
3. `roaming_attach_check(path, imsi=..., home_plmn=...)` for a roamer.
4. `gtp_sessions(path, imsi=...)` and `gtp_ies(path, imsi=...)` for a rejected Create Session.
5. `cause_lookup(protocol, code)` for every code quoted.

Stop at the first failure that explains the rest.
