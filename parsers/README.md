# Parser grammars & fixtures

The parser implementations live in `backend/app/parsers/` and their
per-format positive/negative fixtures live inline in
`backend/app/tests/test_parsers.py`, next to the assertions that use them —
a parser test is far easier to read and maintain when the sample payload is
visible beside the expected extraction.

This directory is therefore reserved for parser material that is genuinely
*shared* beyond the backend test suite: the synthetic attack-scenario
corpus the log generator will emit (spec §36, Phase 20) and any grammar
files a standalone collector needs. It is intentionally empty until
something actually has two consumers — a fixtures directory maintained for
one caller is just indirection.

Supported formats today: JSON, syslog (RFC 3164 + 5424), CEF, LEEF, Windows
Event XML, Apache/Nginx access logs, generic `key=value`. Adding one is
described at the top of `backend/app/parsers/base.py`.
