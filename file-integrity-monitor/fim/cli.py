"""Command line interface: init, check and update."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .core import DEFAULT_EXCLUDES, BaselineError, compare, load_baseline, save_baseline, scan

KEY_ENV = "FIM_KEY"
EXIT_CLEAN, EXIT_CHANGED, EXIT_ERROR = 0, 1, 2


def _key() -> bytes | None:
    value = os.environ.get(KEY_ENV)
    return value.encode() if value else None


def _excludes(args: argparse.Namespace) -> tuple[str, ...]:
    patterns = list(DEFAULT_EXCLUDES) + list(args.exclude)
    # Never report the baseline itself as a change when it lives inside the scanned folder.
    try:
        patterns.append(args.baseline.resolve().relative_to(args.root.resolve()).as_posix())
    except ValueError:
        pass
    return tuple(patterns)


def cmd_init(args: argparse.Namespace) -> int:
    if args.baseline.exists() and not args.force:
        print(f"error: {args.baseline} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_ERROR
    files = scan(args.root, _excludes(args))
    save_baseline(args.baseline, args.root, files, _key())
    print(f"baseline saved: {len(files)} files -> {args.baseline}")
    if not _key():
        print(f"warning: {KEY_ENV} not set, so the baseline is unsigned and could be edited unnoticed")
    return EXIT_CLEAN


def cmd_check(args: argparse.Namespace) -> int:
    baseline = load_baseline(args.baseline, _key())
    report = compare(baseline, scan(args.root, _excludes(args)))

    if args.json:
        print(json.dumps({"clean": report.clean, **report.to_dict()}, indent=2))
    elif report.clean:
        print(f"OK: {len(baseline)} files unchanged")
    else:
        for label, paths in (("MODIFIED", report.modified), ("ADDED", report.added), ("REMOVED", report.removed)):
            for p in paths:
                print(f"{label:<9} {p}")
        print(f"\n{len(report.modified)} modified, {len(report.added)} added, {len(report.removed)} removed")
    return EXIT_CLEAN if report.clean else EXIT_CHANGED


def cmd_update(args: argparse.Namespace) -> int:
    # Verify the old baseline first so an attacker cannot launder changes through 'update'.
    load_baseline(args.baseline, _key())
    files = scan(args.root, _excludes(args))
    save_baseline(args.baseline, args.root, files, _key())
    print(f"baseline updated: {len(files)} files")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File integrity monitor: detect added, removed and modified files with SHA-256.",
        epilog=f"Set {KEY_ENV} to sign the baseline with HMAC-SHA256 so tampering is detected.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("root", type=Path, help="folder to monitor")
    common.add_argument("-b", "--baseline", type=Path, help="baseline file (default: <root>/.fim-baseline.json)")
    common.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths")

    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", parents=[common], help="record a new baseline")
    p.add_argument("--force", action="store_true", help="overwrite an existing baseline")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("check", parents=[common], help="compare the folder with the baseline")
    p.add_argument("--json", action="store_true", help="machine readable output")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("update", parents=[common], help="accept current state as the new baseline")
    p.set_defaults(func=cmd_update)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    if args.baseline is None:
        args.baseline = args.root / ".fim-baseline.json"
    try:
        return args.func(args)
    except BaselineError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
