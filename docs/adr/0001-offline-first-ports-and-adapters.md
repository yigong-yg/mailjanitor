# ADR 0001: Offline-first ports and adapters

- **Status:** Accepted
- **Date:** 2026-08-03
- **Deciders:** Project owner and maintainers
- **Technical area:** Architecture, security, provider integration

## Context

mailjanitor must classify a personal Outlook mailbox using metadata only and
must never mutate a mailbox item without exact, per-item owner approval. The
available provider paths have materially different behavior:

- Microsoft Graph is testable and cloud-native, but requires an app
  registration, OAuth consent, network access, and deliberately scoped tokens.
- Classic Outlook COM avoids a new cloud app but is Windows-only, exposes a
  large mutable object model, can be fragile, and may trigger synchronization
  when Outlook starts.
- UI automation is especially difficult to test and cannot reliably guarantee
  that bodies, attachments, or unintended controls remain untouched.

Choosing either Graph or COM too early would couple classification and approval
logic to provider identity, errors, and lifecycle. Running classification
directly against a live mailbox would also make results difficult to reproduce
and would leave a writer too close to attacker-controlled mailbox content.

The project is for one owner on one machine. A distributed service architecture
would add authentication, deployment, network, and consistency problems without
creating a useful trust boundary.

## Decision

Adopt an **offline-first modular monolith with ports and adapters**.

### 1. Immutable local snapshots are the analysis boundary

A provider-specific reader maps a fixed, metadata-only projection into a sealed
`MailboxSnapshot`. All normalization, classification, review, and proposal
generation operates on that snapshot without provider access. An incomplete or
invalid snapshot cannot produce an action proposal.

Offline-first means analysis and review are local and replayable. It does not
mean mailbox acquisition or approved execution can occur without the selected
provider connection.

### 2. Read and write authority are separate ports

Define narrow `MailboxReader` and `MailboxWriter` ports:

- the reader supports typed metadata paging and a constrained freshness read;
- the writer supports capability discovery, one sealed command at a time, and
  reconciliation of an ambiguous result;
- neither port exposes a raw provider client, query language, arbitrary MAPI
  property, generic command payload, body, or attachment API.

The classifier and proposal compiler never receive a writer. Only the
approval-gated execution use case may resolve one.

### 3. The core is provider-neutral but not identity-blind

Core artifacts retain an opaque adapter kind, profile ID, provider item
locator, and freshness token. A proposal is bound to the adapter/profile that
created it and cannot be executed through a different adapter. Capability
negotiation rejects unsupported semantics instead of approximating them.

This is a semantic common port, not a promise that Graph and COM identifiers or
side effects are interchangeable.

### 4. Classification is deterministic and side-effect free

The baseline classifier is a pure, local rules pipeline over versioned metadata
schemas and content-addressed rule/policy packs. It has no network, clock,
randomness, SDK, COM, LLM, or writer dependency. Every outcome includes stable
rule evidence and can be reproduced from the sealed inputs.

### 5. Mutation requires sealed artifacts and a durable write barrier

The lifecycle is:

`snapshot -> classification -> proposal -> per-line approval -> precondition -> intent journal -> one write -> reconciliation -> receipt`

The proposal and each line are content-digested. An approval explicitly names
and approves or rejects each line and binds those digests. Wildcard approval and
implicit approval by omission do not exist. Before a write, the executor checks
fresh mailbox state and durably records intent. It never blindly retries an
ambiguous provider result.

### 6. Provider adapters are optional and explicitly selected

Graph and COM are mutually optional adapter extras with a shared contract test
suite. Configuration selects exactly one adapter/profile for a run. There is no
automatic detection or fallback.

- A Graph adapter may use only owner-consented, least-privilege delegated
  scopes, a body-free metadata projection, and OS-protected token storage.
- A COM adapter may read only explicit metadata properties and may not launch
  Outlook, automate UI, or access body/attachment object members implicitly.

The owner will select which adapter is built first. This ADR deliberately does
not decide that product/security tradeoff.

### 7. One local state store, one owner-local sanitized audit projection

Use standard-library SQLite under the owner's application-data directory for
exact operational state and crash recovery. Keep secrets in the OS credential
store. Project the required append-only execution trail into a separate,
owner-only operational ledger using opaque IDs and digests rather than new
sender, subject, header, token, or provider-ID data.

The distinction is intentional: local state supports exact reconciliation;
the separate ledger supports human accountability without turning Git into a
mailbox-data store. The repository may contain synthetic examples only.

The detailed boundaries and failure behavior are specified in
[the system design](../architecture/system-design.md).

## Consequences

### Positive

- Most development and every default test can run against synthetic fixtures
  without mailbox access or credentials.
- Provider choice can change before implementation without rewriting triage and
  approval logic.
- Read-only analysis cannot accidentally acquire write authority through an SDK
  object leaked into the core.
- Sealed inputs, canonical serialization, and evidence-bearing rules make runs
  reviewable and reproducible.
- Per-line commands, durable intent, freshness checks, and reconciliation limit
  damage from stale state, crashes, and provider ambiguity.
- A single local process and SQLite store keep deployment and dependencies lean.

### Negative and accepted tradeoffs

- Provider adapters must perform careful mapping and pass a substantial contract
  suite; the ports do not erase Graph/COM differences.
- A snapshot may be stale by review time, so execution must re-read every target
  and may reject approved lines.
- Per-item approval and one-at-a-time writes are slower than bulk automation.
  That friction is a deliberate safety property.
- SQLite state plus a sanitized owner-local audit projection stores two views
  of execution. They serve different recovery and accountability needs and must
  be kept correlated by digest.
- Offline rules cannot use live reputation feeds. Unknown evidence is routed to
  review rather than guessed.
- Local hash chaining detects edits but is not independently tamper-proof.

## Alternatives considered

### Direct Graph-first implementation

Rejected as the core architecture. Graph may still be the selected adapter, but
binding core models to Graph IDs, paging, ETags, SDK objects, and OAuth would
make offline fixtures less representative and provider choice expensive.

### Direct Classic Outlook COM implementation

Rejected as the core architecture. COM may still be the selected adapter, but
letting Outlook objects flow inward would make accidental body access and hidden
side effects harder to prevent, and would make the core Windows-only.

### UI automation

Rejected. UI state is hard to validate or replay, selection can expose message
content, modal dialogs create ambiguous outcomes, and exact mutations are less
reliable than an API/COM contract.

### Analyze and mutate in one live pass

Rejected. It collapses the review boundary, makes classification dependent on
changing mailbox state, and risks turning a classifier result directly into a
write.

### Online service or microservices

Rejected. A hosted control plane would expand the secrets, privacy, identity,
operations, and network attack surface for a single-owner tool. Process-level
modules provide the needed separation.

### Lowest-common-denominator provider abstraction

Rejected. Pretending Graph and COM have identical IDs, concurrency, and move
semantics would make the abstraction unsafe. The chosen ports use common
commands plus explicit capabilities, provider-bound locators, and fail-closed
behavior.

### LLM-first classification

Rejected for the baseline. Mail text is attacker-controlled, model behavior is
not byte-reproducible, and no opaque classifier should be in the authorization
path. A future isolated enrichment component could emit non-authoritative
evidence only, under a separate ADR.

## Guardrails for implementation

The architecture decision is considered violated if any implementation:

- introduces body or attachment-content fields into a core/port schema;
- passes provider SDK or COM objects beyond an adapter;
- allows triage or rendering code to resolve a writer;
- represents wildcard, bulk, or implicit owner approval;
- executes through an adapter/profile other than the proposal's source;
- retries an unknown write result without reconciliation;
- auto-expands OAuth permissions, auto-launches Outlook, follows a link, or
  falls back to UI automation;
- logs raw mailbox content, credentials, or exact provider IDs to the repo;
- requires live mailbox access for the default unit/contract test suite.

Any exception requires a superseding ADR and an explicit owner decision.

## Validation plan

Before a live reader is added:

1. Prove deterministic snapshot replay and byte-stable proposal generation with
   synthetic, defanged fixtures.
2. Prove forbidden fields and generic provider payloads fail schema validation.
3. Prove no dry-run composition root contains a writer.
4. Prove approval digest mismatch, omission, expiry, and stale preconditions
   prevent execution.
5. Exercise success, definite failure, ambiguous result, crash, recovery, and
   partial execution against the fake writer.
6. Run the same port contract suite against the owner-selected adapter in an
   isolated synthetic mailbox/store before any production proposal.

## Revisit conditions

Revisit this ADR only if the product becomes multi-user/hosted, a provider
cannot implement safe freshness or reconciliation semantics, cryptographically
independent approvals become necessary, or a new action cannot fit the sealed
command/capability model without a generic escape hatch.
