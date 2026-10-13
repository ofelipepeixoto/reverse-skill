# Safety boundaries and compatibility

Scope gating and strict privacy start **enabled**. The adapter is still a local
Burp extension, not a sandbox, identity provider or authorization service.

- Strict privacy **denies** tools that read session/history/configuration or may
  return captured traffic. It does not promise regex redaction of arbitrary bodies.
- Local transformations of caller-provided values, version information, scope
  lookup and policy state remain available. Returned caller data is still sensitive.
- With privacy explicitly off, scope gating permits only `send_request` with an
  HTTP(S) URL accepted by Burp's scope API. Methods/headers are checked to prevent
  request-line or routing-header injection. It denies raw requests, bulk operations,
  scans, websockets, scope/config changes and unreviewed tools.
- A client cannot disable either protection unless the operator started Burp with
  `-Dburp.mcp.allowUnrestricted=true`. Even with that startup opt-in, both controls
  initially remain on. This is a compatibility escape hatch for a trusted local
  operator, **not** an approval workflow. Do not use unrestricted mode for shared
  or autonomous-agent deployments.
- These controls affect subsequent dispatches. They do not cancel preexisting Burp
  jobs, user-interface actions or activity of other extensions. Scope changes in
  the Burp UI, global session rules, redirects and host-level egress still require
  independent constraints. No claim of an OS or whole-application sandbox is made.

The bridge bounds request/response/stdio-line bytes to 1 MiB, pending requests to
8 and HTTP calls to a total 30-second deadline. Truncated, timed-out or disconnected
POST calls have an **unknown outcome**; never automatically replay an operation.
Java checks content length before parsing and caps parameter depth/items/strings
and common numeric ranges. These are defensive limits, not capacity benchmarks.
Legacy unrestricted Java operations still have incomplete deadlines/cancellation;
a bridge timeout does not prove that Burp stopped processing the operation.

Proxy listings now retain indices into the original history, through filtering,
reversal and pagination. These are **snapshot-relative indices**, not durable IDs.
Clearing/replacing history can invalidate them; do not persist them as evidence
identity or reuse an old index after the history changes.

## Synthetic regressions

No test below starts Burp, installs offensive tools or contacts a target.

- `node test/safety-boundaries.test.js`: mocked HTTP responses, deadlines, byte
  budgets, input validation, domain errors and pending request limits.
- `./gradlew safetyRegression` with JDK 21: compiles the adapter and exercises
  pure policy and actual dispatch with Montoya mocks, plus history index mapping.
  The test JVM uses a read-only classpath policy and probes denial of sockets,
  host reads/writes and subprocesses before tests. SecurityManager is deprecated;
  this Java-21-only test boundary is not a production isolation recommendation.
- From the repository root: `python3 skills/scripts/test-consolidate-security.py`.
  It exercises a memory filesystem; it does not prove OS filesystem behavior.

A passing synthetic suite does not validate Burp integration, redirection behavior,
agent reasoning, pentest efficacy, throughput or production readiness.
