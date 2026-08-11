# Security analysis

Forge Warden's security analysis is a read-only, advisory layer in the
quality-review pipeline. It is intended to make suspicious code paths visible
during pull-request review; it is not a penetration tester, exploit runner, or
zero-day detector.

## SQL-injection detector

The current detector reports `sql_injection` as a `RISKY` finding when a
common query sink is visibly combined with SQL-like text and dynamic
interpolation, concatenation, formatting, or a JavaScript template
expression. Parameterized calls with a plain query literal and separate bind
arguments are not reported by this direct-pattern detector.

Every finding includes redacted evidence, rationale, a suggested remediation,
and `auto_apply: false`. Risky findings remain human-review-only. The detector
does not execute queries, send payloads, connect to databases, mutate source,
or authorize deployment.

## Coverage and limits

Coverage is deliberately explicit in `quality-review.json`. Python,
JavaScript, and TypeScript receive the direct SQL-sink check; other supported
source languages currently receive the same conservative text-level check.
The detector does not yet perform whole-program taint tracking, framework
configuration analysis, stored-procedure analysis, schema-aware validation,
dynamic query tracing, or compiled-binary inspection.

A clean report means no supported pattern was found in the scanned files. It
does not prove that the application is free of SQL injection or other
vulnerabilities. Use authorized DAST/API fuzzing, dependency and secret
scanning, database-aware integration tests, WAF/runtime telemetry, and manual
security review for defense in depth.

## Safe validation

The fixture suite verifies both an intentionally unsafe query construction and
a parameterized query. Tests operate on temporary files and do not connect to
a database or transmit an injection payload. Future detectors should preserve
the same read-only boundary and add positive and negative fixtures before
being enabled in CI.
