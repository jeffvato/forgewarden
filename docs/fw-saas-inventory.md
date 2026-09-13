# FW-SAAS-001 — SaaS security ownership and fixture inventory

## Current state

ForgeWarden has no canonical FW-SAAS runtime module yet. SaaS requirements are
present in the roadmap, while adjacent accepted controls already own identity,
secret handles, OAuth-consent indicators, policy, Evidence, incidents, AI
security correlation, and Mission Control projection. FW-SAAS must compose
those owners rather than recreate them.

| Concern | Existing canonical owner |
| --- | --- |
| Human, workload, OAuth-app and service-principal identity | FW-ID |
| API token and credential references | FW-KEYS opaque handles |
| OAuth-consent abuse indicators | FW-BME |
| Authorization and bounded proposals | deterministic policy and Action Tickets |
| Security chronology | FW-EVID |
| Cross-domain incidents | FW-SOC |
| AI-application and agent correlation | FW-AID |
| Operator visibility | Mission Control read-only providers |

## First missing boundary

The first substantive gap is a strict caller-supplied SaaS observation
contract. `FW-SAAS-002` will normalize bounded tenant-bound metadata describing
an application, human or non-human principal reference, observation type,
target-resource reference, exact posture/security indicators, and canonical
Evidence reference. Raw tokens, secrets, message/file contents, URLs, provider
responses, and customer data are excluded.

Initial observation types are deliberately bounded to account posture, OAuth
application posture, public sharing, and sign-in risk. Initial exact indicators
cover excessive privilege, dormant account, public share, suspicious sign-in,
risky OAuth consent, unsafe third-party application, and AI application data
access. Classification, cross-domain correlation, and proposal-only response
will follow as separate small requirements after the normalization boundary is
accepted.

## Authority boundary

FW-SAAS-001 and FW-SAAS-002 add no SaaS discovery, provider API, OAuth exchange,
credential or token access, account/session modification, share removal,
application disablement, identity-provider action, network transport,
containment, remediation, deployment, or response execution. Observations are
caller-supplied untrusted data. Results remain `DRY_RUN` and `DETECT_ONLY`.

## Incremental route

1. `FW-SAAS-002`: immutable caller-supplied SaaS observation normalization.
2. `FW-SAAS-003`: exact deterministic posture/threat classification.
3. `FW-SAAS-004`: FW-SOC/FW-AID correlation references.
4. `FW-SAAS-005`: inert policy and Action Ticket-bound response proposals.
5. `FW-SAAS-006`: integrated lifecycle proof and Mission Control projection.

Each requirement receives its own exact candidate, focused validation, and
independent read-only review. Planned IDs do not claim implementation.
