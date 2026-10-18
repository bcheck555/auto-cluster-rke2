#!/usr/bin/env python3
"""Signed offline image lifecycle. Run from the checkout or a verified recipe."""
from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from lab.packer.artifacts import ARTIFACTS, ImageError, operation_lock, verify_manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    lock = sub.add_parser("lock", help="connected preparation of an immutable signed input generation")
    lock.add_argument("--output", type=Path, required=True)
    lock.add_argument("--resume", action="store_true", help="resume only an unsigned, incomplete input generation")
    lock.add_argument("--from-lock", type=Path, help="reuse verified downloads in a new generation with current recipe")
    bundle = sub.add_parser("bundle", help="verify and package an existing signed input generation")
    bundle.add_argument("--lock", type=Path, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    for name in ("build", "test", "publish", "export"):
        command = sub.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with operation_lock():
            if args.operation == "lock":
                from lab.packer.stage import prepare, rebind_recipe
                if args.from_lock:
                    rebind_recipe(args.from_lock, args.output)
                else:
                    prepare(args.output, resume=args.resume)
            elif args.operation == "bundle":
                manifest = verify_manifest(args.lock)
                with tarfile.open(args.output, "x") as archive:
                    for name in sorted(manifest["files"]):
                        archive.add(args.lock.parent / name, arcname=name, recursive=False)
                    for suffix in ("", ".sig"):
                        archive.add(str(args.lock) + suffix, arcname="input.json" + suffix, recursive=False)
                print("verified transfer bundle: " + str(args.output))
            else:
                from lab.packer import pipeline
                getattr(pipeline, args.operation)(args.input, args.output)
        return 0
    except (ImageError, OSError, ValueError, KeyError) as exc:
        print("image operation failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
