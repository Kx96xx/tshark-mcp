---
name: ims-registration-or-sms
description: A UE does not register on IMS, or SMS over IMS is lost or rejected. Use for VoLTE registration problems, 401 loops and RP-ERROR.
---

# IMS registration or SMS over IMS

Get the server's `ims_registration_or_sms` prompt (`path`, `imsi`, `impu`, `number`), or:

1. `ims_registration(path, imsi=... or impu=...)`: verdict per user (registered,
   challenge-loop, failed, expired) and its reasons.
2. `sms_over_ims(path, number=... or imsi=...)`: RP-ACK or RP-ERROR with its cause.
3. `diameter_avps(path, command_code=300)` for the Cx side when the S-CSCF is involved.
4. `cause_lookup(protocol, code)` for RP or SIP causes.
