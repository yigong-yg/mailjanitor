# Operator guide

mailjanitor currently supports sealed, local metadata snapshots only. It has no
live Microsoft Graph, Outlook COM, UI-automation, credential, or mailbox-write
adapter. The proposal, approval, execution, reconciliation, and audit layers are
library foundations for a later adapter; they are intentionally absent from the
CLI until that boundary has a dedicated security review.

## Safe offline workflow

1. Confirm the installed capability surface without probing an account:

   ```powershell
   uv run mailjanitor doctor
   ```

2. Place a synthetic or separately exported canonical snapshot in a protected
   directory outside the repository. A snapshot may contain sender and subject
   metadata, so handle it as sensitive even though bodies and attachment content
   are forbidden by the schema.

3. Classify the snapshot locally:

   ```powershell
   uv run mailjanitor classify C:\protected\snapshot.json
   uv run mailjanitor classify C:\protected\snapshot.json --json
   ```

   Reports expose ordinal item numbers, buckets, rule identifiers, and digests.
   They deliberately omit raw subjects, addresses, and provider identifiers.

4. Review findings as evidence, not instructions. No classification authorizes
   a mailbox mutation, and no text originating in a message can grant approval.

## Local state and keys

Future adapter hosts must place the SQLite operational database, lock files,
JSONL audit ledger, HMAC approval key, and exact provider identifiers in a
protected per-user directory outside the repository. The current library does
not invent a default key store or silently fall back to a repository path.

- Restrict filesystem permissions to the operating user.
- Store approval keys in an OS credential facility, not environment files,
  command history, snapshots, logs, or Git.
- Back up operational state and its protected audit-tail anchor together.
- Treat sanitized JSONL audit projections as integrity evidence, not as the
  crash-recovery source of truth.

After an unclean shutdown, do not retry a write blindly. Inspect the durable
intent, query current state through a read-only adapter, and reconcile the exact
desired postcondition. A stale profile lock should be removed only after an
operator has established that no mailjanitor process or execution is active.

## Provider-adapter decision

The first live adapter remains an explicit owner decision:

- Microsoft Graph offers a stable API but introduces OAuth registration,
  consent, token storage, and connected-application review obligations.
- Classic Outlook COM stays local and avoids a new cloud application, but it is
  Windows-specific, depends on a running Outlook profile, and has weaker
  operational isolation.

Neither option may add a UI-automation fallback. A live adapter must pass
wrong-account, capability, paging-completeness, optimistic-concurrency,
outcome-unknown, and reconciliation tests against a disposable synthetic
mailbox before production use.

## Release verification

Run all gates before sharing an artifact:

```powershell
uv sync --locked --all-groups
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy
uv run --frozen pytest
uv build --no-sources
uv run --no-project python scripts/verify_distribution.py dist
```

The distribution verifier rejects unexpected top-level material, workstation
handoffs, agent configuration, operational databases, audit logs, links, path
traversal, and duplicate wheel members. Inspect `git diff --cached` separately;
a safe package manifest does not make unrelated repository content publishable.
