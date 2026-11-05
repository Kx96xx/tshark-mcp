---
order: 540
readme: Why a roamer cannot attach or get a bearer: each attempt's steps, the ULA subscription held against the Create Session, checks and a verdict
llms: why a roamer cannot attach or get a bearer. One row per attach or PDN attempt with the visited PLMN, access (RAT, TAI, ECGI), steps (S6a AIR/ULR, MAP SAI/UL/UGL, Create Session, Modify Bearer, Gx CCR-I, PFCP establishment) with result, `ref` and frames, the ULA subscription against the Create Session request, `checks` (APN subscribed, PDN type, home routing or local breakout, RAT, ODB, AMBR), `first_failure` and `verdict`. `home_plmn` overrides the home network read from the IMSI. No authentication vectors.
---

Why a roamer cannot attach or get a bearer. The subscriber's steps (S6a AIR/AIA and ULR/ULA, MAP
sendAuthenticationInfo, updateLocation and updateGprsLocation, GTPv2-C Create Session and Modify
Bearer, Gx CCR-I/CCA-I, PFCP Session Establishment) grouped into `attempts` in time order (a new
attempt when authentication or a location update follows a location update or PDN step, or a Create
Session repeats an APN). Each attempt: `visited_plmn` (ULR Visited-PLMN-Id, GTPv2 Serving Network,
or the MAP peer GT) with `visited_source`, `roaming`, `access` (RAT, TAI, ECGI), `steps` with
result, code, `ref`, `cause_lookup` call, Error-Diagnostic, offending IE and `likely_causes` of a
GTP reject, the ULA `subscription` digest (`subscription_from_earlier_attempt` when this attempt had
no ULA), the Create Session `request`, `checks` (`pass`, `warn`, `fail` or `unknown`:
authentication, location update, Create Session, ODB, RAT against Access-Restriction-Data, APN
subscribed or wildcard, PDN type requested against subscribed, routing: home routed or local
breakout from the APN operator identifier against VPLMN-Dynamic-Address-Allowed, APN-AMBR within the
subscription), `first_failure` and a one-sentence `verdict`. `home_plmn` ("MCC-MNC") overrides the
home network read from the IMSI (the MNC length follows the MCC). Content-free: authentication
vectors are counted, never returned
