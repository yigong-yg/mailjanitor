# Sanitized action audit examples

This directory is reserved for documentation and deliberately synthetic audit
examples. A real append-only JSONL ledger belongs in owner-only operational
storage outside the repository. The target local operational database—not this
directory—is the source of truth for crash recovery and exact provider
identifiers. The current pre-release database stores only digests, pseudonyms,
status, and the protected audit anchor; it is not sufficient for a live writer.

Action records must never contain raw mailbox addresses, message or folder
identifiers, sender values, subjects, headers, bodies, attachment data,
credentials, tokens, provider exceptions, or approval keys. The application
must not write operational records here, stage them, or commit them
automatically.

No mailbox action has been recorded merely because this directory exists.
