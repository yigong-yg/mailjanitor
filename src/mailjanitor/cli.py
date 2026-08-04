"""Safe, offline-first command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from mailjanitor import __version__
from mailjanitor.snapshot_io import SnapshotFormatError, load_snapshot
from mailjanitor.triage.classifier import IncompleteSnapshotError, classify_snapshot

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TextIO

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INVALID_DATA = 3
EXIT_INCOMPLETE_SNAPSHOT = 4


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI without initializing a mailbox adapter."""
    parser = argparse.ArgumentParser(
        prog="mailjanitor",
        description="Offline-first, metadata-only mailbox triage",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("version", help="show the installed version")

    doctor = subcommands.add_parser(
        "doctor",
        help="report local capabilities without connecting to a mailbox",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit machine-readable JSON",
    )

    classify = subcommands.add_parser(
        "classify",
        help="classify one sealed local snapshot without connecting to a mailbox",
    )
    classify.add_argument("snapshot", type=Path, help="canonical snapshot JSON path")
    classify.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit a redacted machine-readable report",
    )
    return parser


def _doctor_report() -> dict[str, object]:
    """Describe compiled capabilities without probing accounts or credentials."""
    return {
        "schema_version": 1,
        "version": __version__,
        "operating_mode": "offline_only",
        "mailbox_connection_attempted": False,
        "live_reader_adapters": [],
        "live_writer_adapters": [],
        "mail_body_modelled": False,
        "attachment_content_modelled": False,
        "default_action_mode": "dry_run",
    }


def _write_doctor(report: dict[str, object], *, as_json: bool, stream: TextIO) -> None:
    if as_json:
        stream.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
        stream.write("\n")
        return

    stream.write(f"mailjanitor {report['version']}\n")
    stream.write("mode: offline-only; no mailbox connection attempted\n")
    stream.write("live adapters: none\n")
    stream.write("default action mode: dry-run\n")


def _classification_report(snapshot_path: Path) -> dict[str, object]:
    snapshot = load_snapshot(snapshot_path)
    result = classify_snapshot(snapshot)
    bucket_counts: dict[str, int] = {}
    findings: list[dict[str, object]] = []
    for item_index, classification in enumerate(result.classifications, start=1):
        bucket = classification.primary_bucket.value
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        findings.append(
            {
                "item_index": item_index,
                "primary_bucket": bucket,
                "labels": [label.value for label in classification.labels],
                "evidence": [
                    {
                        "rule_id": evidence.rule_id,
                        "severity": evidence.severity,
                        "signals": list(evidence.signals),
                    }
                    for evidence in classification.evidence
                ],
            }
        )
    return {
        "schema_version": 1,
        "snapshot_digest": result.snapshot_digest,
        "policy_digest": result.policy_digest,
        "classifier_version": result.classifier_version,
        "message_count": len(result.classifications),
        "bucket_counts": dict(sorted(bucket_counts.items())),
        "findings": findings,
        "contains_raw_message_metadata": False,
        "mailbox_connection_attempted": False,
    }


def _write_classification(
    report: dict[str, object], *, as_json: bool, stream: TextIO
) -> None:
    if as_json:
        stream.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
        stream.write("\n")
        return
    stream.write("mailjanitor offline classification\n")
    stream.write(f"messages: {report['message_count']}\n")
    counts = report["bucket_counts"]
    if isinstance(counts, dict):
        stream.writelines(f"{bucket}: {count}\n" for bucket, count in counts.items())
    stream.write("raw message metadata: omitted\n")
    stream.write("mailbox connection attempted: no\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run a command and return a process exit code."""
    args = build_parser().parse_args(argv)
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr

    if args.command == "version":
        output.write(f"mailjanitor {__version__}\n")
        return EXIT_OK
    if args.command == "doctor":
        _write_doctor(_doctor_report(), as_json=args.as_json, stream=output)
        return EXIT_OK
    if args.command == "classify":
        try:
            report = _classification_report(args.snapshot)
        except IncompleteSnapshotError:
            errors.write("classification refused: snapshot is incomplete\n")
            return EXIT_INCOMPLETE_SNAPSHOT
        except SnapshotFormatError:
            errors.write("classification refused: snapshot format is invalid\n")
            return EXIT_INVALID_DATA
        _write_classification(report, as_json=args.as_json, stream=output)
        return EXIT_OK

    return EXIT_USAGE
