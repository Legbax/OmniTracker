"""
Parse the X.509 cert chain (hd0) embedded in an Argos attestation bundle.

Input: a captured `*_argos_ciphertext_*.bin` blob from layer5_argos.js.
Output: structure of the bundle, all certs in the chain, and extracted
        Android Key Attestation IDs (the trackable territory).

Field 12 of the Argos wire is what `iew.mpi.e` returns. Outer structure
(empirical from 2026-04-29 capture):

    f1 LEN(11)  : header (version/timestamp/type/flags)
    f2 LEN(316) : signature blob (likely from Keystore)
    f6 LEN(2548): cert chain — multi-cert concat or proto-of-cert

We parse f6 as a sequence of DER certificates (look for repeated 0x30 0x82
SEQUENCE+long-form-length headers) and extract the Android Key Attestation
extension (OID 1.3.6.1.4.1.11129.2.1.17) from each cert that has it.

KeyDescription ASN.1:
    KeyDescription ::= SEQUENCE {
        attestationVersion         INTEGER,
        attestationSecurityLevel   ENUMERATED,
        keyMintVersion             INTEGER,
        keyMintSecurityLevel       ENUMERATED,
        attestationChallenge       OCTET_STRING,
        uniqueId                   OCTET_STRING,
        softwareEnforced           AuthorizationList,
        teeEnforced                AuthorizationList,
    }

Trackable AuthorizationList tags (where ID leaks could occur):
    [710] attestationIdBrand        — usually expected (real device)
    [711] attestationIdDevice       — usually expected
    [712] attestationIdProduct      — usually expected
    [713] attestationIdSerial       — TRACKABLE (must be spoofed)
    [714] attestationIdImei         — TRACKABLE (must be spoofed)
    [715] attestationIdMeid         — TRACKABLE
    [716] attestationIdManufacturer — usually expected
    [717] attestationIdModel        — usually expected

Per the user memory: BRAND/MODEL/DEVICE/PRODUCT/MANUFACTURER are expected
to match the real device when the spoofing profile maps to it. SERIAL/IMEI
are the IDs that must be rotated.
"""
import os
import sys
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier

KEY_ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

ATTESTATION_ID_TAGS = {
    700: "attestationApplicationId",
    701: "(reserved)",
    702: "(reserved)",
    703: "(reserved)",
    704: "(reserved)",
    705: "(reserved)",
    706: "(reserved)",
    707: "(reserved)",
    708: "(reserved)",
    709: "(reserved)",
    710: "attestationIdBrand",
    711: "attestationIdDevice",
    712: "attestationIdProduct",
    713: "attestationIdSerial",         # trackable
    714: "attestationIdImei",           # trackable
    715: "attestationIdMeid",           # trackable
    716: "attestationIdManufacturer",
    717: "attestationIdModel",
    718: "vendorPatchLevel",
    719: "bootPatchLevel",
    720: "deviceUniqueAttestation",
    723: "attestationIdSecondImei",     # trackable
    400: "rollbackResistant",
    400: "rollbackResistance",
    503: "creationDateTime",
    509: "rootOfTrust",
    701: "(reserved)",
    702: "(reserved)",
}

TRACKABLE_TAGS = {713, 714, 715, 723}


def decode_varint(data, pos):
    v = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint overflow")
    raise ValueError("truncated varint")


def parse_proto_top_level(data):
    """Walk top-level proto fields without recursing."""
    fields = []
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:
            v, pos = decode_varint(data, pos)
            fields.append({"f": field_num, "wire": "VARINT", "v": v})
        elif wire_type == 1:
            v = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            fields.append({"f": field_num, "wire": "I64", "v": v})
        elif wire_type == 2:
            ln, pos = decode_varint(data, pos)
            chunk = data[pos:pos + ln]
            pos += ln
            fields.append({"f": field_num, "wire": "LEN", "len": ln, "bytes": chunk})
        elif wire_type == 5:
            v = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            fields.append({"f": field_num, "wire": "I32", "v": v})
        else:
            fields.append({"f": field_num, "wire": f"WIRE{wire_type}", "skip_remainder": True})
            break
    return fields


def find_der_certs(data):
    """Scan for X.509 DER certs.
    A DER cert starts with SEQUENCE (0x30) followed by long-form length
    (0x82 + 2 bytes) for typical X.509 sizes (256B - 64KB).
    Returns list of (offset, length, der_bytes).
    """
    certs = []
    pos = 0
    while pos < len(data) - 4:
        if data[pos] == 0x30 and data[pos + 1] == 0x82:
            length = struct.unpack_from(">H", data, pos + 2)[0]
            total = length + 4  # tag + length(0x82+2) + content
            if pos + total > len(data):
                pos += 1
                continue
            # Try to parse it
            der = data[pos:pos + total]
            try:
                cert = x509.load_der_x509_certificate(der, default_backend())
                certs.append((pos, total, der, cert))
                pos += total
                continue
            except Exception:
                pass
        pos += 1
    return certs


def parse_asn1_authorization_list(data, depth=0):
    """Walk AuthorizationList SEQUENCE { tagged_field, ... }.
    Each field is [tag] EXPLICIT { value }.
    Returns dict: tag_num -> bytes/int/list.
    """
    out = {}
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        tag_byte = data[pos]
        pos += 1
        # Context-specific tag, constructed: 0xA0 + tag low 5 bits, OR multi-byte tag
        tag_class = tag_byte >> 6
        tag_constructed = (tag_byte >> 5) & 1
        tag_num_low = tag_byte & 0x1F
        if tag_num_low == 0x1F:
            # multi-byte tag
            tag_num = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                tag_num = (tag_num << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
        else:
            tag_num = tag_num_low

        if pos >= len(data):
            break
        len_byte = data[pos]
        pos += 1
        if len_byte & 0x80:
            num_octets = len_byte & 0x7F
            length = 0
            for _ in range(num_octets):
                length = (length << 8) | data[pos]
                pos += 1
        else:
            length = len_byte

        if pos + length > len(data):
            break
        content = data[pos:pos + length]
        pos += length

        # Skip to inner content for [N] EXPLICIT — strip the inner ASN.1 type wrapper
        # The outer is context-tagged. The inner is the raw value (INTEGER, OCTET_STRING, SET, etc.).
        if tag_class == 2:  # context-specific
            out[tag_num] = content
    return out


def parse_inner_value(content, expected_type=None):
    """Parse the inner ASN.1 value inside an EXPLICIT-tagged AuthorizationList field.
    The content starts with the inner ASN.1 tag (e.g. 0x04 for OCTET_STRING, 0x02 INTEGER).
    """
    if not content:
        return None
    inner_tag = content[0]
    pos = 1
    if pos >= len(content):
        return None
    len_byte = content[pos]
    pos += 1
    if len_byte & 0x80:
        n = len_byte & 0x7F
        length = 0
        for _ in range(n):
            length = (length << 8) | content[pos]
            pos += 1
    else:
        length = len_byte
    inner = content[pos:pos + length]

    if inner_tag == 0x04:  # OCTET_STRING
        return inner
    elif inner_tag == 0x02:  # INTEGER
        return int.from_bytes(inner, "big", signed=False)
    elif inner_tag == 0x0A:  # ENUMERATED
        return int.from_bytes(inner, "big", signed=False)
    elif inner_tag == 0x31:  # SET
        return inner  # raw — needs further parse
    elif inner_tag == 0x30:  # SEQUENCE
        return inner  # raw
    elif inner_tag == 0x05:  # NULL
        return "NULL"
    return inner  # raw bytes


def render_value(v, tag):
    if v is None:
        return "<empty>"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, bytes):
        if tag in ATTESTATION_ID_TAGS:
            # Try to decode as utf-8 string (these are typically text IDs)
            try:
                s = v.decode("utf-8")
                if all(0x20 <= ord(c) < 0x7F for c in s):
                    return repr(s)
            except UnicodeDecodeError:
                pass
        return v.hex() + (f" ({len(v)}B)" if len(v) > 16 else "")
    return repr(v)


def parse_key_attestation_ext(ext_data):
    """Parse the Android Key Attestation extension (KeyDescription)."""
    # The extension value is OCTET_STRING wrapping a DER SEQUENCE
    if ext_data[0] == 0x30:
        seq_data = ext_data
    else:
        # strip OCTET_STRING wrapper
        if ext_data[0] != 0x04:
            print("  unexpected extension wrapper:", hex(ext_data[0]))
            return None
        # length
        len_byte = ext_data[1]
        if len_byte & 0x80:
            n = len_byte & 0x7F
            content_start = 2 + n
        else:
            content_start = 2
        seq_data = ext_data[content_start:]

    # seq_data starts with 0x30 (SEQUENCE) followed by length
    if seq_data[0] != 0x30:
        return None
    if seq_data[1] & 0x80:
        n = seq_data[1] & 0x7F
        content_start = 2 + n
    else:
        content_start = 2
    inner = seq_data[content_start:]

    # Parse the SEQUENCE of 8 fields:
    # version (INTEGER), securityLevel (ENUMERATED), keymint version, keymint sec level,
    # challenge (OCTET_STRING), uniqueId (OCTET_STRING),
    # softwareEnforced (SEQUENCE), teeEnforced (SEQUENCE)
    fields = []
    pos = 0
    while pos < len(inner) and len(fields) < 8:
        if pos >= len(inner):
            break
        tag = inner[pos]
        pos += 1
        len_byte = inner[pos]
        pos += 1
        if len_byte & 0x80:
            n = len_byte & 0x7F
            length = 0
            for _ in range(n):
                length = (length << 8) | inner[pos]
                pos += 1
        else:
            length = len_byte
        content = inner[pos:pos + length]
        pos += length
        fields.append((tag, content))

    if len(fields) < 8:
        print(f"  KeyDescription incomplete ({len(fields)} fields)")
        return None

    result = {
        "attestationVersion": int.from_bytes(fields[0][1], "big"),
        "attestationSecurityLevel": int.from_bytes(fields[1][1], "big"),
        "keyMintVersion": int.from_bytes(fields[2][1], "big"),
        "keyMintSecurityLevel": int.from_bytes(fields[3][1], "big"),
        "attestationChallenge": fields[4][1],
        "uniqueId": fields[5][1],
        "softwareEnforced_raw": fields[6][1],
        "teeEnforced_raw": fields[7][1],
    }
    result["softwareEnforced"] = parse_asn1_authorization_list(fields[6][1])
    result["teeEnforced"] = parse_asn1_authorization_list(fields[7][1])
    return result


def render_authlist(label, al):
    print(f"\n  {label}:")
    if not al:
        print("    <empty>")
        return
    flagged_real = []
    for tag in sorted(al.keys()):
        name = ATTESTATION_ID_TAGS.get(tag, f"(unknown tag {tag})")
        v = parse_inner_value(al[tag])
        if isinstance(v, bytes):
            try:
                s = v.decode("utf-8")
                if all(0x20 <= ord(c) < 0x7F for c in s):
                    rendered = repr(s)
                else:
                    rendered = v.hex() + f" ({len(v)}B)"
            except UnicodeDecodeError:
                rendered = v.hex() + f" ({len(v)}B)"
        else:
            rendered = repr(v)
        marker = ""
        if tag in TRACKABLE_TAGS:
            marker = "  ← TRACKABLE"
        print(f"    [{tag}] {name:<32} = {rendered}{marker}")
        # Heuristic: flag if value looks like a known real ID for merlinx Claro
        if tag == 714 and isinstance(v, bytes):
            s = v.decode("latin1", errors="replace")
            if "865" in s or "356" in s:  # IMEI prefixes for the test device
                flagged_real.append(f"IMEI {s}")


def main():
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        # Default: latest ciphertext blob
        blobdir = Path("D:/Claude Projects/OmniTracker/captures/argos_blobs")
        blobs = sorted(
            (b for b in blobdir.iterdir() if "ciphertext" in b.name and b.suffix == ".bin"),
            key=lambda p: p.stat().st_mtime,
        )
        if not blobs:
            print("No ciphertext blobs found")
            sys.exit(1)
        target = blobs[-1]

    print(f"=== Target: {target.name} ===")
    print(f"Size: {target.stat().st_size} bytes")
    print()

    data = target.read_bytes()

    # 1. Parse outer proto
    print("--- Outer proto ---")
    fields = parse_proto_top_level(data)
    for f in fields:
        if f["wire"] == "LEN":
            head = f["bytes"][:8].hex()
            print(f"  f{f['f']} LEN({f['len']}) head={head}")
        else:
            print(f"  f{f['f']} {f['wire']} v={f.get('v')}")

    # Find the cert-chain field (largest LEN field — typically f6)
    chain_field = None
    for f in fields:
        if f["wire"] == "LEN" and f["len"] > 1000:
            if chain_field is None or f["len"] > chain_field["len"]:
                chain_field = f

    if not chain_field:
        print("\nNo cert-chain candidate field found")
        sys.exit(1)

    print(f"\n--- Cert chain candidate: f{chain_field['f']} ({chain_field['len']}B) ---")
    chain_bytes = chain_field["bytes"]

    # 2. Find DER certs inside the chain blob
    certs = find_der_certs(chain_bytes)
    print(f"  Found {len(certs)} X.509 DER cert(s)")
    print()

    for i, (off, total, der, cert) in enumerate(certs):
        print(f"=== Cert #{i+1} @ offset 0x{off:x} ({total}B) ===")
        print(f"  Subject: {cert.subject.rfc4514_string()}")
        print(f"  Issuer:  {cert.issuer.rfc4514_string()}")
        print(f"  Serial:  {cert.serial_number}")
        print(f"  NotBefore/After: {cert.not_valid_before_utc} → {cert.not_valid_after_utc}")
        print(f"  PubKey:  {cert.public_key().__class__.__name__}")
        sig_alg = cert.signature_algorithm_oid._name
        print(f"  SigAlg:  {sig_alg}")

        # Look for Key Attestation extension
        for ext in cert.extensions:
            if ext.oid == KEY_ATTESTATION_OID:
                print(f"\n  *** Android Key Attestation extension present ***")
                ka = parse_key_attestation_ext(ext.value.value)
                if ka:
                    print(f"    attestationVersion:       {ka['attestationVersion']}")
                    print(f"    attestationSecurityLevel: {ka['attestationSecurityLevel']} (0=software,1=TEE,2=StrongBox)")
                    print(f"    keyMintVersion:           {ka['keyMintVersion']}")
                    print(f"    keyMintSecurityLevel:     {ka['keyMintSecurityLevel']}")
                    print(f"    challenge ({len(ka['attestationChallenge'])}B): {ka['attestationChallenge'][:32].hex()}{'...' if len(ka['attestationChallenge'])>32 else ''}")
                    print(f"    uniqueId ({len(ka['uniqueId'])}B):  {ka['uniqueId'].hex() if ka['uniqueId'] else '<empty>'}")
                    render_authlist("softwareEnforced (untrusted, app-controllable)", ka["softwareEnforced"])
                    render_authlist("teeEnforced (TEE-signed, anti-spoof target)", ka["teeEnforced"])
                break
        else:
            # non-leaf cert (chain root or intermediate)
            ext_oids = [e.oid.dotted_string for e in cert.extensions]
            print(f"  Extensions: {ext_oids}")
        print()


if __name__ == "__main__":
    main()
