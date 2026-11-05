- `throughput_timeline`: without `interval`, a capture too long for 10,000 one-second intervals gets
  the smallest round interval that fits (2 s up to 1 day) and `interval_auto: true`, instead of an
  error; an explicit `interval` that gives too many intervals is still refused (public-validation D20).
- `cause_lookup`: new protocols `dns` (RCODEs), `tls` (alert descriptions), `icmp`/`icmpv6`
  (`code="type:code"`) and `http` (status codes), and `nas`, which looks a code up in all four NAS
  tables and lists the other readings in `other_tables` (public-validation D21).
- `find_identifier`: `max_files` defaults to the server's --max-files (it was 20), and a directory
  whose subdirectories hold captures names them in `subdirectories_with_captures` with a note,
  since subdirectories are not searched (public-validation D23).
