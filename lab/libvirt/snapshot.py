"""Capture read-only host evidence before/after a separately authorized apply."""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import uuid
from pathlib import Path


def capture() -> dict:
    evidence: dict = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    def run(command: list[str]) -> str:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        return result.stdout

    virsh = ["virsh", "--connect", "qemu:///system"]
    for kind, listing, dump in (("domains", "list", "dumpxml"),
                                ("networks", "net-list", "net-dumpxml"),
                                ("pools", "pool-list", "pool-dumpxml")):
        names = sorted(name.strip() for name in run(virsh + [listing, "--all", "--name"]).splitlines()
                       if name.strip())
        evidence[kind] = {name: run(virsh + [dump, name]) for name in names}
        evidence[kind + "_status"] = run(virsh + [listing, "--all"])
    filters = {}
    for line in run(virsh + ["nwfilter-list"]).splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            uuid.UUID(fields[0])
        except ValueError:
            continue
        filters[fields[1]] = run(virsh + ["nwfilter-dumpxml", fields[1]])
    evidence["nwfilters"] = filters
    evidence["links"] = json.loads(run(["ip", "-j", "address", "show"]))
    evidence["routes_v4"] = json.loads(run(["ip", "-j", "route", "show", "table", "all"]))
    evidence["routes_v6"] = json.loads(run(["ip", "-j", "-6", "route", "show", "table", "all"]))
    evidence["nftables"] = run(["sudo", "-n", "nft", "list", "ruleset"])
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    evidence = capture()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(evidence, output, indent=2)
        output.write("\n")
    print(f"snapshot saved: {args.output}")


if __name__ == "__main__":
    main()
