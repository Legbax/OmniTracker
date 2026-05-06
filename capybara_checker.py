#!/usr/bin/env python3
"""
Capybara checker
================

End-to-end signup capture + Argos/Register report generator for Snapchat.

Typical live run:
  python capybara_checker.py --pm-clear

Analyze an existing capture directory:
  python capybara_checker.py --analyze-existing captures/signup_outer_rotated_20260503_031625

The live flow starts the stealth Frida helper if needed, launches Snapchat,
attaches the signup_outer probe, captures logcat, waits for the signup
RegisterWithUsernamePassword blob, then writes a Markdown report and a JSON
artifact with full, non-truncated values.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


SNAP_PACKAGE = "com.snapchat.android"
REGISTER_ENDPOINT = "/snapchat.janus.api.RegistrationService/RegisterWithUsernamePassword"
DEFAULT_REMOTE = "127.0.0.1:8443"
DEFAULT_DEVICE_HELPER = "/data/local/tmp/.android-helper"
DEFAULT_DEVICE_LOG = "/data/local/tmp/.helper.log"
SUSFS_MARKER = "/data/local/tmp/.susfs_omni_applied"

TRACKER_DIR = Path(__file__).resolve().parent
OMNISHIELD_DIR = TRACKER_DIR.parent / "OmniShield"
CAPTURES_DIR = TRACKER_DIR / "captures"

ARGOS_SOURCES = [
    OMNISHIELD_DIR / "reports" / "ARGOS_OMNISHIELD_ANALYSIS.md",
    OMNISHIELD_DIR / "reports" / "argos_decompile_20260427" / "ARGOS_PROTOBUF_SCHEMA.md",
    OMNISHIELD_DIR / "reports" / "argos_decompile_20260427" / "B_static" / "B_STATIC_FINAL_REPORT.md",
    OMNISHIELD_DIR / "CLAUDE.md",
]


class CapybaraError(RuntimeError):
    pass


@dataclass
class CmdResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def run_cmd(
    args: list[str],
    *,
    cwd: Path = TRACKER_DIR,
    timeout: int = 30,
    check: bool = False,
) -> CmdResult:
    result = subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    out = CmdResult(args, result.returncode, result.stdout.strip(), result.stderr.strip())
    if check and result.returncode != 0:
        cmd = " ".join(args)
        raise CapybaraError(f"Command failed ({result.returncode}): {cmd}\n{out.stderr or out.stdout}")
    return out


def adb(*args: str, timeout: int = 30, check: bool = False) -> CmdResult:
    return run_cmd(["adb", *args], timeout=timeout, check=check)


def adb_su(command: str, *, timeout: int = 30, check: bool = False) -> CmdResult:
    return adb("shell", "su", "-c", command, timeout=timeout, check=check)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def full_hex(data: bytes) -> str:
    return data.hex()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def printable_utf8(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(ch in "\r\n\t" or 32 <= ord(ch) < 127 or ord(ch) >= 160 for ch in text):
        return text
    return None


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    return sorted(set(s.decode("latin1") for s in re.findall(rb"[ -~]{" + str(min_len).encode() + rb",}", data)))


def read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while offset < len(buf):
        b = buf[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, offset
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    raise ValueError("unexpected EOF while reading varint")


def parse_proto(buf: bytes) -> list[tuple[int, int, Any]]:
    offset = 0
    items: list[tuple[int, int, Any]] = []
    while offset < len(buf):
        key, offset = read_varint(buf, offset)
        if key == 0:
            raise ValueError("protobuf key 0")
        field_no = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            value, offset = read_varint(buf, offset)
            items.append((field_no, wire_type, value))
        elif wire_type == 1:
            end = offset + 8
            if end > len(buf):
                raise ValueError("fixed64 EOF")
            items.append((field_no, wire_type, buf[offset:end]))
            offset = end
        elif wire_type == 2:
            length, offset = read_varint(buf, offset)
            end = offset + length
            if end > len(buf):
                raise ValueError("length-delimited EOF")
            items.append((field_no, wire_type, buf[offset:end]))
            offset = end
        elif wire_type == 5:
            end = offset + 4
            if end > len(buf):
                raise ValueError("fixed32 EOF")
            items.append((field_no, wire_type, buf[offset:end]))
            offset = end
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return items


def can_parse_proto(buf: bytes) -> bool:
    if not buf:
        return False
    try:
        parse_proto(buf)
        return True
    except Exception:
        return False


def group_fields(items: list[tuple[int, int, Any]]) -> dict[int, list[tuple[int, Any]]]:
    grouped: dict[int, list[tuple[int, Any]]] = {}
    for field_no, wire_type, value in items:
        grouped.setdefault(field_no, []).append((wire_type, value))
    return grouped


def first_bytes(fields: dict[int, list[tuple[int, Any]]], field_no: int) -> bytes | None:
    values = fields.get(field_no) or []
    if values and values[0][0] == 2:
        return values[0][1]
    return None


def first_varint(fields: dict[int, list[tuple[int, Any]]], field_no: int) -> int | None:
    values = fields.get(field_no) or []
    if values and values[0][0] == 0:
        return values[0][1]
    return None


def first_string(fields: dict[int, list[tuple[int, Any]]], field_no: int) -> str | None:
    data = first_bytes(fields, field_no)
    return printable_utf8(data) if data is not None else None


def bytes_value(data: bytes) -> dict[str, Any]:
    text = printable_utf8(data)
    return {
        "length": len(data),
        "sha256": sha256_hex(data),
        "hex": full_hex(data),
        "base64": b64(data),
        "utf8": text,
    }


def proto_scalar(wire_type: int, value: Any) -> Any:
    if wire_type == 0:
        return value
    if isinstance(value, bytes):
        text = printable_utf8(value)
        return text if text is not None else bytes_value(value)
    return value


def parse_x509_cert(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "length": len(data),
        "sha256": sha256_hex(data),
        "der_hex": full_hex(data),
        "der_base64": b64(data),
    }
    try:
        from cryptography import x509
    except ImportError:
        result["parse_error"] = "cryptography is not installed"
        return result

    try:
        cert = x509.load_der_x509_certificate(data)
    except Exception as exc:
        result["parse_error"] = str(exc)
        return result

    result.update(
        {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": hex(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "extensions": [],
        }
    )

    for ext in cert.extensions:
        item: dict[str, Any] = {
            "oid": ext.oid.dotted_string,
            "critical": ext.critical,
        }
        raw = getattr(ext.value, "value", None)
        if isinstance(raw, bytes):
            item.update(
                {
                    "length": len(raw),
                    "sha256": sha256_hex(raw),
                    "hex": full_hex(raw),
                    "base64": b64(raw),
                    "strings": extract_ascii_strings(raw, min_len=3),
                }
            )
        else:
            item["repr"] = repr(ext.value)
        result["extensions"].append(item)
    return result


def parse_register_blob(blob_path: Path) -> dict[str, Any]:
    data = blob_path.read_bytes()
    root = group_fields(parse_proto(data))

    birth: dict[str, Any] = {}
    birth_data = first_bytes(root, 5)
    if birth_data:
        birth_fields = group_fields(parse_proto(birth_data))
        birth = {
            "year": first_varint(birth_fields, 1),
            "month": first_varint(birth_fields, 2),
            "day": first_varint(birth_fields, 3),
            "raw": bytes_value(birth_data),
        }

    context_data = first_bytes(root, 15) or b""
    context_fields = group_fields(parse_proto(context_data)) if context_data else {}

    f7: dict[str, Any] = {}
    f7_data = first_bytes(context_fields, 7)
    if f7_data and can_parse_proto(f7_data):
        f7_fields = group_fields(parse_proto(f7_data))
        f7 = {
            "f1": first_string(f7_fields, 1),
            "f2": first_string(f7_fields, 2),
            "f3": first_varint(f7_fields, 3),
            "f4": first_string(f7_fields, 4),
            "raw": bytes_value(f7_data),
        }

    f9_varints: list[int] = []
    f9_data = first_bytes(context_fields, 9)
    if f9_data and can_parse_proto(f9_data):
        f9_fields = group_fields(parse_proto(f9_data))
        f9_varints = [value for wire_type, value in f9_fields.get(1, []) if wire_type == 0]

    f10: dict[str, Any] = {}
    f10_data = first_bytes(context_fields, 10)
    if f10_data and can_parse_proto(f10_data):
        f10_fields = group_fields(parse_proto(f10_data))
        f10["raw"] = bytes_value(f10_data)
        f10["f3"] = bytes_value(first_bytes(f10_fields, 3) or b"")
        f10_f2_data = first_bytes(f10_fields, 2)
        if f10_f2_data and can_parse_proto(f10_f2_data):
            f10_f2_fields = group_fields(parse_proto(f10_f2_data))
            f10["f2"] = {
                "raw": bytes_value(f10_f2_data),
                "f1": bytes_value(first_bytes(f10_f2_fields, 1) or b""),
                "f2": bytes_value(first_bytes(f10_f2_fields, 2) or b""),
                "f3": bytes_value(first_bytes(f10_f2_fields, 3) or b""),
                "f4": first_varint(f10_f2_fields, 4),
            }

    f12: dict[str, Any] = {}
    f12_data = first_bytes(context_fields, 12)
    if f12_data and can_parse_proto(f12_data):
        f12_fields = group_fields(parse_proto(f12_data))
        f12["raw"] = bytes_value(f12_data)
        for sub_no in (1, 2, 6):
            sub = first_bytes(f12_fields, sub_no)
            if sub is not None:
                f12[f"f{sub_no}"] = bytes_value(sub)

    f16_blocks: list[dict[str, Any]] = []
    for index, (wire_type, block_data) in enumerate(context_fields.get(16, []), start=1):
        if wire_type != 2:
            f16_blocks.append({"index": index, "wire_type": wire_type, "value": block_data})
            continue
        block: dict[str, Any] = {"index": index, "raw": bytes_value(block_data)}
        if can_parse_proto(block_data):
            block_fields = group_fields(parse_proto(block_data))
            for sub_no, values in sorted(block_fields.items()):
                key = f"f{sub_no}"
                parsed_values = []
                for sub_wire_type, sub_value in values:
                    if sub_no == 13 and sub_wire_type == 2 and isinstance(sub_value, bytes):
                        parsed_values.append(parse_x509_cert(sub_value))
                    else:
                        parsed_values.append(proto_scalar(sub_wire_type, sub_value))
                block[key] = parsed_values[0] if len(parsed_values) == 1 else parsed_values
        f16_blocks.append(block)

    root_unknown: dict[str, Any] = {}
    for field_no, values in sorted(root.items()):
        key = f"f{field_no}"
        root_unknown[key] = [proto_scalar(wire_type, value) for wire_type, value in values]

    context_known = {
        "f1": first_string(context_fields, 1),
        "f2": first_string(context_fields, 2),
        "f3": first_string(context_fields, 3),
        "f4": first_string(context_fields, 4),
        "f7": f7,
        "f8": first_string(context_fields, 8),
        "f9_varints": f9_varints,
        "f10": f10,
        "f12": f12,
        "f15": first_varint(context_fields, 15),
        "f16": f16_blocks,
        "f19": first_string(context_fields, 19),
    }

    return {
        "path": str(blob_path),
        "length": len(data),
        "sha256": sha256_hex(data),
        "hex": full_hex(data),
        "base64": b64(data),
        "strings": extract_ascii_strings(data),
        "root": {
            "f1": first_string(root, 1),
            "f2": first_string(root, 2),
            "f3": first_string(root, 3),
            "f4": first_string(root, 4),
            "f5_birth": birth,
            "f6": first_string(root, 6),
            "f7": first_string(root, 7),
            "f8": first_varint(root, 8),
            "f15_context": {
                "length": len(context_data),
                "sha256": sha256_hex(context_data) if context_data else None,
                "hex": full_hex(context_data),
                "base64": b64(context_data),
                **context_known,
            },
            "f16": first_varint(root, 16),
            "f17": first_varint(root, 17),
            "all_fields": root_unknown,
        },
    }


def load_events(capture_dir: Path) -> list[dict[str, Any]]:
    events_path = capture_dir / "events.jsonl"
    events: list[dict[str, Any]] = []
    if not events_path.exists():
        return events
    with events_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def find_register_event(capture_dir: Path) -> tuple[dict[str, Any], Path]:
    register_events = [
        event for event in load_events(capture_dir)
        if event.get("endpoint") == REGISTER_ENDPOINT
    ]
    if not register_events:
        raise CapybaraError(f"No RegisterWithUsernamePassword event found in {capture_dir}")
    event = max(register_events, key=lambda item: int(item.get("body_length") or 0))
    blob_file = event.get("blob_file")
    if not blob_file:
        raise CapybaraError("Register event has no blob_file")
    blob_path = capture_dir / blob_file
    if not blob_path.exists():
        raise CapybaraError(f"Register blob missing: {blob_path}")
    return event, blob_path


def parse_omnishield_log(logcat_path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {"raw_matches": [], "grpc_dumps": []}
    if not logcat_path.exists():
        return values

    patterns: list[tuple[str, re.Pattern[str], Any]] = [
        ("appset_id", re.compile(r"\[AppSetID\] spoofed=(\S+)"), lambda m: m.group(1)),
        ("oaid", re.compile(r"\[OAID\] spoofed=(\S+)"), lambda m: m.group(1)),
        ("gaid", re.compile(r"\[GAID\] spoofed=(\S+)"), lambda m: m.group(1)),
        ("account_email", re.compile(r"\[AccountHide\] email=(\S+) enabled=(\S+)"), lambda m: {"email": m.group(1), "enabled": m.group(2)}),
        ("imei", re.compile(r"\[VecB\] spoofedImei0=(\S+) spoofedImei1=(\S+)"), lambda m: {"imei0": m.group(1), "imei1": m.group(2)}),
        ("gsf_id", re.compile(r"\[VecF\] spoofedGsfId=(\S+)"), lambda m: m.group(1)),
        ("sim_profile", re.compile(r"\[ChileSIM\] realPlmn=(\S+) carrier=(\S+) plmn=(\S+) iso=(\S+) use_real_telephony=(\S+) use_sim_pool=(\S+)"), lambda m: {
            "real_plmn": m.group(1), "carrier": m.group(2), "plmn": m.group(3), "iso": m.group(4),
            "use_real_telephony": m.group(5), "use_sim_pool": m.group(6),
        }),
        ("ssaid_cached", re.compile(r"\[PR-SSAID-JNI\] cached ssaid=([0-9a-fA-F]+) \(seed=(\d+)\)"), lambda m: {"ssaid": m.group(1), "seed": m.group(2)}),
        ("phys_id", re.compile(r"\[PR-PhysID\] wifiMac=(\S+) btMac=(\S+) bssid=(\S+)"), lambda m: {"wifi_mac": m.group(1), "bt_mac": m.group(2), "bssid": m.group(3)}),
        ("sim_identity", re.compile(r"\[ChileSIM\] IMSI=(\S+) ICCID=(\S+) Phone=(\S+) ccLen=(\S+) pool=(\S+)"), lambda m: {
            "imsi": m.group(1), "iccid": m.group(2), "phone": m.group(3), "cc_len": m.group(4), "pool": m.group(5),
        }),
        ("pinned_location", re.compile(r"\[PR-LocCfg\] loaded pinned coords: lat=([-\d.]+) lon=([-\d.]+) alt=([-\d.]+)"), lambda m: {
            "lat": m.group(1), "lon": m.group(2), "alt": m.group(3),
        }),
        ("real_ssaid_loaded", re.compile(r"\[PR-SsaidSeal\] real SSAID loaded for .*?: ([0-9a-fA-F]+)"), lambda m: m.group(1)),
        ("ssaid_disk_snapshot", re.compile(r"\[PR-SSAIDDyn\] disk-snapshot for .*?: real=([0-9a-fA-F]+) spoofed=([0-9a-fA-F]+)"), lambda m: {
            "real": m.group(1), "spoofed": m.group(2),
        }),
        ("install_fake", re.compile(r"\[PR-InstallFake\] loaded real=(\d+) spoofed=(\d+)"), lambda m: {"real": m.group(1), "spoofed": m.group(2)}),
        ("location_cache", re.compile(r"\[PR130\] Location cache: lat=([-\d.]+) lon=([-\d.]+) cached=(\S+) profile='([^']+)' seed=(\d+)"), lambda m: {
            "lat": m.group(1), "lon": m.group(2), "cached": m.group(3), "profile": m.group(4), "seed": m.group(5),
        }),
        ("timezone", re.compile(r"TimeZone\.setDefault\(([^)]+)\)"), lambda m: m.group(1)),
        ("locale", re.compile(r"Locale\.setDefault\(([^)]+)\)"), lambda m: m.group(1)),
        ("system_integrity", re.compile(r"System Integrity loaded\. Profile: ([^|]+) \| LTE: ([^|]+) \| GPS: (.+)$"), lambda m: {
            "profile": m.group(1).strip(), "lte": m.group(2).strip(), "gps": m.group(3).strip(),
        }),
        ("grpc_dump", re.compile(r"\[PR-GrpcDump\] URI: (\S+)\s+payload: (\d+) bytes"), lambda m: {"uri": m.group(1), "payload_bytes": m.group(2)}),
    ]

    with logcat_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for name, pattern, convert in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                converted = convert(match)
                if name == "grpc_dump":
                    values["grpc_dumps"].append(converted)
                    if converted.get("uri") == REGISTER_ENDPOINT:
                        values["grpc_register_dump"] = converted
                else:
                    values[name] = converted
                values["raw_matches"].append({"key": name, "line": line.rstrip("\n")})
    return values


def blob_plaintext_hits(capture_dir: Path, values: dict[str, Any]) -> dict[str, list[str]]:
    candidates: dict[str, str] = {}

    def add(prefix: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            if len(value) >= 4:
                candidates[prefix] = value
            return
        if isinstance(value, dict):
            for key, inner in value.items():
                add(f"{prefix}.{key}", inner)
            return

    for key, value in values.items():
        if key != "raw_matches":
            add(key, value)

    hits: dict[str, list[str]] = {}
    blobs = sorted((capture_dir / "argos_blobs").glob("*.bin"))
    for key, value in candidates.items():
        needle = value.encode("utf-8", errors="ignore")
        if not needle:
            continue
        found = [blob.name for blob in blobs if needle in blob.read_bytes()]
        hits[f"{key}={value}"] = found
    return hits


def endpoint_summary(capture_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in load_events(capture_dir):
        blob_file = event.get("blob_file")
        blob_path = capture_dir / blob_file if blob_file else None
        strings: list[str] = []
        if blob_path and blob_path.exists():
            strings = extract_ascii_strings(blob_path.read_bytes())
        rows.append(
            {
                "timestamp": event.get("timestamp"),
                "endpoint": event.get("endpoint"),
                "body_length": event.get("body_length"),
                "blob_file": blob_file,
                "body_diag": event.get("body_diag"),
                "strings": strings,
            }
        )
    return rows


def capture_warnings(analysis: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    event_endpoints = {row.get("endpoint") for row in analysis.get("endpoints", [])}
    grpc_dumps = analysis.get("omnishield", {}).get("grpc_dumps", [])
    for dump in grpc_dumps:
        uri = dump.get("uri")
        if uri and uri not in event_endpoints:
            warnings.append(
                f"Logcat PR-GrpcDump saw {uri} ({dump.get('payload_bytes')} bytes), "
                "but Frida signup_outer did not persist a blob for it."
            )

    context = analysis.get("register", {}).get("root", {}).get("f15_context", {})
    f16_blocks = context.get("f16") or []
    timeout_blocks = []
    for index, block in enumerate(f16_blocks, start=1):
        if isinstance(block, dict) and block.get("f4") == "time-out":
            timeout_blocks.append(str(index))
    if timeout_blocks:
        warnings.append(
            "Register f15.f16 attestation block(s) "
            + ", ".join(timeout_blocks)
            + " reported f4='time-out'; cert-chain values are absent in this signup."
        )
    return warnings


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("\n", "<br>") for cell in row) + " |")
    return "\n".join(out)


def code_block(text: str, lang: str = "text") -> str:
    return f"```{lang}\n{text}\n```"


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def write_report(capture_dir: Path, analysis: dict[str, Any]) -> Path:
    register = analysis["register"]
    root = register["root"]
    context = root["f15_context"]
    omni = analysis["omnishield"]

    lines: list[str] = []
    lines.append("# Capybara Checker - Informe Final")
    lines.append("")
    lines.append("Lei los analisis de Argos del repo y los cruce con el `RegisterWithUsernamePassword` capturado pre-TLS. Los campos `fN` son numeros protobuf inferidos, porque no tenemos el `.proto` nominal. La captura valida es Frida `signup_outer`; el log C++/OmniShield se usa como corroboracion cuando existe `[PR-GrpcDump]`.")
    lines.append("")
    lines.append("## Fuentes Principales")
    for source in ARGOS_SOURCES:
        lines.append(f"- `{source}`")

    lines.append("")
    lines.append("## Captura")
    lines.append(md_table(
        ["Campo", "Valor"],
        [
            ["Endpoint", REGISTER_ENDPOINT],
            ["Payload", f"{register['length']} bytes"],
            ["SHA256", register["sha256"]],
            ["Blob", register["path"]],
            ["Frida diag", analysis["register_event"].get("body_diag", "")],
            ["OmniShield PR-GrpcDump", compact_json((omni.get("grpc_register_dump") or {}))],
        ],
    ))

    if analysis.get("warnings"):
        lines.append("")
        lines.append("## Advertencias De Captura")
        for warning in analysis["warnings"]:
            lines.append(f"- {warning}")

    birth = root.get("f5_birth") or {}
    lines.append("")
    lines.append("## Campos Directos De Signup")
    lines.append(md_table(
        ["Campo", "Valor", "Origen"],
        [
            ["f1", root.get("f1"), "Formulario signup, nombre/display name"],
            ["f2", repr(root.get("f2")), "Campo textual secundario"],
            ["f3", root.get("f3"), "Username elegido"],
            ["f4", root.get("f4"), "Password capturado antes de TLS"],
            ["f5.f1", birth.get("year"), "Ano nacimiento"],
            ["f5.f2", birth.get("month"), "Mes nacimiento"],
            ["f5.f3", birth.get("day"), "Dia nacimiento"],
            ["f6", root.get("f6"), "Pais/locale visible"],
            ["f7", root.get("f7"), "Timezone visible"],
            ["f8", root.get("f8"), "Enum interno de signup/client flow"],
            ["f15", f"{context.get('length')} bytes sha256={context.get('sha256')}", "Contexto grande cliente/Argos/attestation"],
            ["f16", root.get("f16"), "Flag interno desconocido"],
            ["f17", root.get("f17"), "Enum/version interna desconocida"],
        ],
    ))

    f7 = context.get("f7") or {}
    f10 = context.get("f10") or {}
    f12 = context.get("f12") or {}
    f16_blocks = context.get("f16") or []
    block1 = f16_blocks[0] if len(f16_blocks) >= 1 else {}
    block2 = f16_blocks[1] if len(f16_blocks) >= 2 else {}
    lines.append("")
    lines.append("## Contexto f15")
    lines.append(md_table(
        ["Campo", "Valor", "Interpretacion"],
        [
            ["f15.f1", context.get("f1"), "ID generado por Snap app"],
            ["f15.f2", context.get("f2"), "ID interno Snap"],
            ["f15.f3", context.get("f3"), "ID interno Snap"],
            ["f15.f4", context.get("f4"), "ID interno Snap"],
            ["f15.f7.f1", repr(f7.get("f1")), "Campo vacio/textual"],
            ["f15.f7.f2", f7.get("f2"), "Token/nonce Snap"],
            ["f15.f7.f3", f7.get("f3"), "Enum/contador interno Snap"],
            ["f15.f7.f4", repr(f7.get("f4")), "Campo vacio/textual"],
            ["f15.f8", context.get("f8"), "ID Snap reutilizado en endpoints del signup"],
            ["f15.f9", f"{len(context.get('f9_varints') or [])} varints", "SupProperties.impressionCountIds; no son fingerprint hashes"],
            ["f15.f10.f3", (f10.get("f3") or {}).get("hex"), "Bytes que contienen prefijo + SSAID spoofed"],
            ["f15.f12", ", ".join(f"{key}={val['length']}B" for key, val in f12.items() if key.startswith("f")), "Bloque Argos/cifrado interno Snap"],
            ["f15.f15", context.get("f15"), "Flag interno"],
            ["f15.f16[1].f5", block1.get("f5"), "Package name real"],
            ["f15.f16[2].f5", block2.get("f5"), "Package name real"],
            ["f15.f16[2].f11", block2.get("f11"), "Token/challenge Snap"],
            ["f15.f16[2].f12", block2.get("f12"), "Token/challenge Snap / cert extension"],
            ["f15.f19", context.get("f19"), "Otro ID interno Snap"],
        ],
    ))

    lines.append("")
    lines.append("### f15.f9 Completo")
    lines.append(code_block(",".join(str(v) for v in context.get("f9_varints") or [])))

    lines.append("")
    lines.append("## Valores OmniShield Correlacionados")
    omni_rows: list[list[Any]] = []
    hits = analysis["plaintext_hits"]
    for key, value in omni.items():
        if key in ("raw_matches", "grpc_dumps"):
            continue
        flattened = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, dict) else str(value)
        hit_text = []
        for hit_key, hit_files in hits.items():
            if hit_key.startswith(f"{key}=") or hit_key.startswith(f"{key}."):
                hit_text.append(f"{hit_key}: {', '.join(hit_files) if hit_files else 'no plaintext'}")
        omni_rows.append([key, flattened, "<br>".join(hit_text)])
    lines.append(md_table(["Valor", "Fuente OmniShield/logcat", "Donde aparece en blobs"], omni_rows))

    lines.append("")
    lines.append("## PR-GrpcDump Logcat")
    grpc_rows = []
    for item in omni.get("grpc_dumps", []):
        grpc_rows.append([item.get("uri"), item.get("payload_bytes")])
    lines.append(md_table(["URI", "Payload bytes"], grpc_rows))

    lines.append("")
    lines.append("## Argos / Attestation")
    lines.append("El bloque Argos no viaja como PII plano. Segun el analisis actualizado del repo, OmniShield no edita Argos directamente: hace que las lecturas base que Snap usa salgan spoofed/coherentes por Layers 1/3/4/10.")
    ssaid = (omni.get("ssaid_cached") or {}).get("ssaid") if isinstance(omni.get("ssaid_cached"), dict) else None
    f10_f3_hex = (f10.get("f3") or {}).get("hex")
    cert_subject = None
    try:
        cert_subject = block2["f13"][0].get("subject")
    except Exception:
        cert_subject = None
    lines.append("")
    lines.append(code_block(
        "\n".join(
            [
                f"OmniShield SSAID spoofed: {ssaid}",
                f"Payload f15.f10.f3:      {f10_f3_hex}",
                f"Cert subject CN:         {cert_subject}",
            ]
        )
    ))

    lines.append("")
    lines.append("## Certificados f15.f16[2].f13")
    cert_rows: list[list[Any]] = []
    certs = block2.get("f13") or []
    if isinstance(certs, dict):
        certs = [certs]
    for index, cert in enumerate(certs, start=1):
        cert_rows.append([
            index,
            cert.get("length"),
            cert.get("sha256"),
            cert.get("subject"),
            cert.get("issuer"),
            cert.get("serial"),
            f"{cert.get('not_valid_before')} -> {cert.get('not_valid_after')}",
        ])
    lines.append(md_table(["#", "Len", "SHA256", "Subject", "Issuer", "Serial", "Validity"], cert_rows))

    lines.append("")
    lines.append("## Android KeyDescription / Extension Strings")
    for index, cert in enumerate(certs, start=1):
        for ext in cert.get("extensions", []):
            strings = ext.get("strings") or []
            if strings:
                lines.append(f"### Cert {index} extension {ext.get('oid')} len={ext.get('length')} sha256={ext.get('sha256')}")
                lines.append(code_block("\n".join(strings)))

    lines.append("")
    lines.append("## Otros Endpoints Del Signup")
    endpoint_rows = []
    for endpoint in analysis["endpoints"]:
        endpoint_rows.append([
            endpoint.get("timestamp"),
            endpoint.get("endpoint"),
            endpoint.get("body_length"),
            endpoint.get("blob_file"),
            "; ".join(endpoint.get("strings") or []),
        ])
    lines.append(md_table(["Timestamp", "Endpoint", "Bytes", "Blob", "Strings completos"], endpoint_rows))

    lines.append("")
    lines.append("## Valores Completos Sin Truncar")
    lines.append("Los siguientes bloques preservan los valores largos que normalmente se omiten en el chat.")
    long_values = {
        "register_hex": register["hex"],
        "register_base64": register["base64"],
        "f15_context_hex": context["hex"],
        "f15_context_base64": context["base64"],
        "f15_f10": f10,
        "f15_f12": f12,
        "f15_f16_blocks": f16_blocks,
        "register_ascii_strings": register["strings"],
    }
    lines.append(code_block(json.dumps(long_values, ensure_ascii=False, indent=2), "json"))

    report_path = capture_dir / "capybara_report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def analyze_capture(capture_dir: Path) -> tuple[Path, Path]:
    capture_dir = capture_dir.resolve()
    register_event, register_blob = find_register_event(capture_dir)
    register = parse_register_blob(register_blob)
    logcat_path = capture_dir / "logcat_full.log"
    omni = parse_omnishield_log(logcat_path)
    analysis = {
        "capture_dir": str(capture_dir),
        "generated_at": datetime.now().isoformat(),
        "register_event": register_event,
        "register": register,
        "omnishield": omni,
        "plaintext_hits": blob_plaintext_hits(capture_dir, omni),
        "endpoints": endpoint_summary(capture_dir),
        "sources": [str(path) for path in ARGOS_SOURCES],
    }
    analysis["warnings"] = capture_warnings(analysis)
    values_path = capture_dir / "capybara_values.json"
    values_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path = write_report(capture_dir, analysis)
    return report_path, values_path


def frida_remote_ok(remote: str) -> bool:
    result = run_cmd(["frida-ps", "-H", remote], timeout=8, check=False)
    return result.returncode == 0


def ensure_stealth_frida(remote: str, *, force_restart: bool = False, apply_susfs: bool = True) -> None:
    host, _, port = remote.partition(":")
    if not port:
        raise CapybaraError(f"remote must be HOST:PORT, got {remote}")
    if not force_restart and frida_remote_ok(remote):
        print(f"[capybara] Frida stealth already reachable at {remote}")
        return

    helper = TRACKER_DIR / "bin" / "frida-stealth"
    if not helper.exists():
        raise CapybaraError(f"Missing stealth helper: {helper}")

    print("[capybara] Starting stealth Frida helper")
    adb("push", str(helper), DEFAULT_DEVICE_HELPER, timeout=90, check=True)
    adb_su(f"pkill -9 -f android-helper 2>/dev/null || true", timeout=10)
    adb("forward", "--remove", f"tcp:{port}", timeout=10)
    adb_su(f"chmod 755 {DEFAULT_DEVICE_HELPER}", check=True)
    launch_cmds = [
        f"nohup {DEFAULT_DEVICE_HELPER} -l 127.0.0.1:{port} -D >{DEFAULT_DEVICE_LOG} 2>&1 &",
        f"{DEFAULT_DEVICE_HELPER} -l 127.0.0.1:{port} -D >{DEFAULT_DEVICE_LOG} 2>&1 &",
    ]
    pids = ""
    for launch_cmd in launch_cmds:
        adb_su(launch_cmd, timeout=10, check=True)
        time.sleep(2)
        pids = adb_su("pgrep -af android-helper", timeout=10).stdout
        if pids:
            break
    if not pids:
        helper_log = adb("shell", "cat", DEFAULT_DEVICE_LOG, timeout=10).stdout
        raise CapybaraError(f"Frida helper did not start. Device log:\n{helper_log}")
    adb("forward", f"tcp:{port}", f"tcp:{port}", timeout=10, check=True)

    if apply_susfs:
        has_susfs = adb_su("command -v ksu_susfs >/dev/null 2>&1 && echo OK || true", timeout=10).stdout
        marker_present = adb_su(f"[ -f {SUSFS_MARKER} ] && echo YES || true", timeout=10).stdout
        if "OK" in has_susfs and "YES" not in marker_present:
            for command in (
                f"add_sus_path {DEFAULT_DEVICE_HELPER}",
                f"add_sus_path_loop {DEFAULT_DEVICE_HELPER}",
                f"add_sus_kstat {DEFAULT_DEVICE_HELPER}",
                f"add_sus_path {DEFAULT_DEVICE_LOG}",
                f"add_sus_kstat {DEFAULT_DEVICE_LOG}",
                "hide_sus_mnts_for_non_su_procs 1",
            ):
                adb_su(f"ksu_susfs {command} 2>&1 || true", timeout=10)
            adb_su(f"touch {SUSFS_MARKER}", timeout=10)

    if not frida_remote_ok(remote):
        raise CapybaraError(f"Frida remote did not become reachable at {remote}")


def launch_snap(*, pm_clear: bool) -> int:
    if pm_clear:
        print("[capybara] pm clear com.snapchat.android")
        adb("shell", "pm", "clear", SNAP_PACKAGE, timeout=60, check=True)
    else:
        adb("shell", "am", "force-stop", SNAP_PACKAGE, timeout=15)

    print("[capybara] Launching Snapchat")
    adb("shell", "monkey", "-p", SNAP_PACKAGE, "-c", "android.intent.category.LAUNCHER", "1", timeout=30, check=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pid = adb("shell", "pidof", SNAP_PACKAGE, timeout=5).stdout.strip()
        if pid:
            return int(pid.split()[0])
        time.sleep(1)
    raise CapybaraError("Snapchat did not start within 30s")


def start_logcat(capture_dir: Path) -> subprocess.Popen:
    adb("logcat", "-c", timeout=10)
    out = (capture_dir / "logcat_full.log").open("w", encoding="utf-8", errors="replace")
    err = (capture_dir / "logcat_err.log").open("w", encoding="utf-8", errors="replace")
    return subprocess.Popen(["adb", "logcat", "-v", "threadtime"], stdout=out, stderr=err, text=True)


def start_monitor(capture_dir: Path, remote: str) -> subprocess.Popen:
    stdout = (capture_dir / "frida_console.log").open("w", encoding="utf-8", errors="replace")
    stderr = (capture_dir / "frida_stderr.log").open("w", encoding="utf-8", errors="replace")
    events = capture_dir / "events.jsonl"
    return subprocess.Popen(
        [
            sys.executable,
            str(TRACKER_DIR / "android_monitor.py"),
            "--remote",
            remote,
            "--package",
            SNAP_PACKAGE,
            "--attach",
            "--layers",
            "signup_outer",
            "--output",
            str(events),
        ],
        cwd=str(TRACKER_DIR),
        stdout=stdout,
        stderr=stderr,
        text=True,
    )


def wait_for_hook(capture_dir: Path, monitor: subprocess.Popen, timeout: int = 30) -> None:
    console = capture_dir / "frida_console.log"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if monitor.poll() is not None:
            stderr = (capture_dir / "frida_stderr.log").read_text(encoding="utf-8", errors="replace")
            stdout = console.read_text(encoding="utf-8", errors="replace") if console.exists() else ""
            raise CapybaraError(f"android_monitor.py exited early\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
        if console.exists() and "signup_outer probe armed" in console.read_text(encoding="utf-8", errors="replace"):
            return
        time.sleep(1)
    raise CapybaraError("signup_outer hook did not arm within timeout")


def wait_for_register(capture_dir: Path, timeout: int, post_register_seconds: int) -> None:
    events_path = capture_dir / "events.jsonl"
    deadline = time.monotonic() + timeout if timeout > 0 else None
    seen_at: float | None = None
    print("[capybara] Complete el signup en el telefono. Esperando RegisterWithUsernamePassword...")
    while True:
        if deadline is not None and time.monotonic() > deadline:
            raise CapybaraError("Timed out waiting for RegisterWithUsernamePassword")
        events = load_events(capture_dir)
        if any(event.get("endpoint") == REGISTER_ENDPOINT for event in events):
            if seen_at is None:
                seen_at = time.monotonic()
                print(f"[capybara] Register capturado. Esperando {post_register_seconds}s para endpoints posteriores...")
            elif time.monotonic() - seen_at >= post_register_seconds:
                return
        time.sleep(1)


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def live_capture(args: argparse.Namespace) -> Path:
    capture_dir = CAPTURES_DIR / f"capybara_{now_stamp()}"
    (capture_dir / "argos_blobs").mkdir(parents=True, exist_ok=True)
    print(f"[capybara] Capture dir: {capture_dir}")

    ensure_stealth_frida(args.remote, force_restart=args.restart_frida, apply_susfs=not args.no_susfs)
    logcat_proc: subprocess.Popen | None = None
    monitor_proc: subprocess.Popen | None = None
    try:
        logcat_proc = start_logcat(capture_dir)
        pid = launch_snap(pm_clear=args.pm_clear)
        print(f"[capybara] Snapchat PID: {pid}")
        monitor_proc = start_monitor(capture_dir, args.remote)
        wait_for_hook(capture_dir, monitor_proc)
        wait_for_register(capture_dir, args.timeout, args.post_register_seconds)
    except KeyboardInterrupt:
        print("\n[capybara] Interrumpido por usuario; generare informe con lo capturado.")
    finally:
        stop_process(monitor_proc)
        stop_process(logcat_proc)
        time.sleep(0.5)
    return capture_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capybara_checker.py",
        description="Capybara checker: capture Snap signup Argos/Register blobs and generate a full report.",
    )
    parser.add_argument("--analyze-existing", metavar="DIR", help="No captura; genera informe desde un capture dir existente.")
    parser.add_argument("--remote", default=DEFAULT_REMOTE, help=f"Frida stealth host:port. Default: {DEFAULT_REMOTE}")
    parser.add_argument("--pm-clear", action="store_true", help="Ejecuta pm clear antes de lanzar Snapchat.")
    parser.add_argument("--restart-frida", action="store_true", help="Fuerza reinicio del helper stealth Frida.")
    parser.add_argument("--no-susfs", action="store_true", help="No aplica reglas ksu_susfs para ocultar helper.")
    parser.add_argument("--timeout", type=int, default=900, help="Segundos maximos esperando el Register. 0 = sin limite.")
    parser.add_argument("--post-register-seconds", type=int, default=35, help="Segundos extra para capturar endpoints posteriores.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.analyze_existing:
            capture_dir = Path(args.analyze_existing)
        else:
            capture_dir = live_capture(args)
        report_path, values_path = analyze_capture(capture_dir)
        print(f"[capybara] Report: {report_path}")
        print(f"[capybara] Full JSON: {values_path}")
        return 0
    except CapybaraError as exc:
        print(f"[capybara] ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
