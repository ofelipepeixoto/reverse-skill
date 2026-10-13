# Safety corrections on the fork

Base: upstream `cab634bd855fc287f6e420c1f36fd1a6b9245960`.
This change is proposed for review; it does not enable tools or deploy a service.

Implemented:

- Enforce scope/privacy at the Burp dispatch boundary, with protected defaults
  and local startup opt-in required before a remote client can disable them.
- Preserve original history indices across filters and reverse ordering.
- Bound bridge bytes, pending calls and deadlines; mark domain errors as errors.
- Validate consolidation IDs, metadata and path containment before writes in
  Python/PowerShell; default to candidate instead of implicit validated.
- Refuse downloads when a hash utility or trusted digest is missing.
- Redact matched values from the leak scanner's output.
- Keep field-journal validation read-only: no automatic merge/comment step.
- Clarify that skills, precedent and scope files do not grant authority.
- Add synthetic regressions and correct the documented routing fixture count.

Remaining limits:

- Consolidation is still a non-transactional legacy supersession rewrite.
  Path preflight is not TOCTOU-safe storage or a hard-link boundary.
- Explicit validated remains a declaration, not authenticated human review.
- Scope gating intentionally denies operations without a reviewed scope boundary.
  The unrestricted compatibility mode is not production-safe isolation.
- Historical indices are not durable IDs across history reset/replacement.
- Burp's existing asynchronous operations are not cancelled by bridge deadlines;
  unrestricted legacy operations need further deadline/cancellation work.
- No host sandbox, multi-tenant authority, LLM eval, dependency vulnerability
  certification, performance benchmark or real-target test is provided.
- Java compilation and mock tests do not certify runtime behavior inside Burp.

Licenses and existing attribution are unchanged: root MIT, src-hunter's own MIT,
and the CTF component's GPLv3 remain in their original locations. No private
inventory, private audit report, credentials or real captured traffic belongs in
this public change.
