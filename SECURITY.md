# Security policy

mailjanitor deliberately processes hostile mailbox metadata. Please report a
suspected vulnerability with a private GitHub security advisory rather than a
public issue. Include the affected version, a minimal synthetic reproducer, and
the expected security invariant. Never include real mailbox content,
credentials, provider identifiers, or approval keys.

The current pre-release line receives security fixes on a best-effort basis.
No live mailbox adapter is included in the baseline release.

The supported trust boundary and required controls are defined in
[`docs/security/threat-model.md`](docs/security/threat-model.md). In
particular, email content is untrusted data and is never an instruction or an
approval channel.
