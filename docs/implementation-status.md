# Implementation status

This ledger keeps target architecture separate from code that is safe to use
today. A component being implemented does not imply authorization to connect to
or mutate a mailbox.

| Capability | Status | Reachability and gate |
| --- | --- | --- |
| Metadata-only domain and bounded snapshot import | Implemented | Local files only; bodies and attachment content are unrepresentable |
| Deterministic classifier and redacted report | Implemented | Reachable through `mailjanitor classify`; public policy has no organization-specific allowlists |
| Safe text, Markdown, address, and spreadsheet rendering | Implemented | Library boundary; proposal UI is not implemented |
| Exact typed proposals and authenticated per-line approvals | Foundation | Library/test use only; no proposal compiler or persistence host |
| Fail-closed serial executor and reconciliation | Foundation | Synthetic adapter tests only; no CLI wiring or live writer |
| SQLite approval/execution state and HMAC JSONL audit | Foundation | Pseudonymous state and full latest-event binding; exact artifact persistence and history-wide semantic replay remain live gates |
| Synthetic reader/writer and fault injection | Implemented | Reserved test data only |
| Graph or Classic Outlook COM reader/writer | Not implemented | Requires explicit owner choice, threat review, disposable-mailbox contract tests, and least-privilege deployment |
| OS credential store, owner-only ACL provisioning, and split approval signer/verifier | Not implemented | Required before any approval or audit key is provisioned |
| Snapshot acquisition and pagination coordinator | Not implemented | Must prove completeness and capability provenance |
| Classification-to-proposal compiler and exact artifact store | Not implemented | Must bind snapshot, policy, rule version, capability set, and every selected action |
| Live mutation command | Prohibited | Remains absent until every live-writer gate above is complete and separately approved |

## Release rule

The offline classifier may be developed and packaged while live-writer gates are
open. No adapter may add UI automation, implicit scope upgrades, bulk selectors,
blind retry, email-derived approval, or a fallback that bypasses these gates.
