"""
DNS PCAP Feature Extractor for NetSentinel
Extracts DNS queries from .pcap and .pcapng files.

================================================================================
FEATURE LINEAGE & ARCHITECTURAL SPECIFICATION
================================================================================
Computes the 14-feature live inference representation used by NetSentinel.

1. 'longest_word' Transformation (Project-Level Feature Engineering):
   - The official CIC-Bell-DNS-EXF-2021 dataset defines 'longest_word' as a
     stateless categorical/token string.
   - To prevent domain/vocabulary memorization and ensure live PCAP compatibility
     across unseen arbitrary domain queries, NetSentinel uses:
     longest_word_len = character length of longest alphanumeric token in domain.
   - This is an explicit project-level feature engineering choice and does NOT
     reproduce the original CIC string attribute.

2. 'sld' Transformation (Project-Level Feature Engineering):
   - The official CIC-Bell-DNS-EXF-2021 dataset defines 'sld' as a stateless
     categorical string containing raw domain names (e.g. 'google', 'amazon',
     or specific exfiltration hashes).
   - NetSentinel engineers:
     sld_len = character length of the extracted SLD.
   - This measures payload expansion (exfiltrated payloads produce unusually
     long SLD segments >= 30 chars) without memorizing specific domain tokens.

3. 'len' Feature Definition & Empirical Validation:
   - The official CIC-Bell-DNS-EXF-2021 documentation defines 'len' as:
     "Length of domain and subdomain."
   - In NetSentinel, this is computed as:
     len = subdomain_length + sld_len + 1
   - Empirical Validation: This exact formula was verified against the real
     CIC-Bell-DNS-EXF-2021 dataset in CN_FINAL/archive/ via scripts/validate_len_formula.py.
     Across all 757,211 rows in all 18 stateless files, it matched with
     100.0000% accuracy (757,211 / 757,211 matches, exactly 0 mismatches).

4. Domain & Subdomain Parsing Policy:
   - Multi-part Public Suffixes: Recognized 2-part ccTLDs (.co.uk, .com.au,
     .org.uk, .co.in, .edu.au, .gov.uk, etc.) are treated as 2-label TLDs.
     The 3rd label from the right is designated as the SLD.
   - Standard Suffixes: The final label is the TLD and the 2nd label from the
     right is the SLD.
   - Subdomain: All labels preceding the SLD. If no labels precede the SLD,
     subdomain_length = 0 and subdomain = 0.
   - Limitation: Non-standard multi-level ccTLD delegations not in the common
     suffix list default to the standard single-part TLD boundary.

5. Capture Format Support & PCAPNG Implementation:
   - Standard PCAP: Supports both Little-Endian (0xa1b2c3d4) and Big-Endian (0xd4c3b2a1).
   - PCAPNG Architecture:
     * Section Header Block (SHB, type 0x0A0D0D0A) byte-order detection (0x1A2B3C4D).
     * Supports multiple Section Header Blocks across a single file (resets interface table).
     * Interface Description Block (IDB, type 0x00000001) parsing (LinkType, SnapLen,
       and option 9 'if_tsresol' timestamp resolution).
     * Enhanced Packet Block (EPB, type 0x00000006) layout compliance:
       offset 0-3: Interface ID
       offset 4-7: Timestamp High
       offset 8-11: Timestamp Low
       offset 12-15: Captured Packet Length
       offset 16-19: Original Packet Length
       offset 20+: Packet Data (padded to 32-bit boundary)
     * Does NOT implement Simple Packet Blocks (SPB). Only EPBs are processed.
     * Interface ID -> LinkType lookup. Supported linktypes: Ethernet (1), Raw IP (12, 101),
       Linux Cooked v1 (113), Linux Cooked v2 (276), NULL/Loopback (0).
     * Unsupported linktypes are explicitly rejected/skipped and logged.

6. Transport & Protocol Limitations:
   - UDP DNS: Supported on port 53.
   - TCP DNS: Extracts DNS query messages available within a single TCP segment
     (with RFC 1035 2-byte length prefix). Does NOT perform multi-segment TCP
     stream reassembly.
   - IPv6: Supports standard IPv6 and implements IPv6 extension header traversal
     (Hop-by-Hop, Routing, Fragment, AH, Destination Options).
   - Unencrypted DNS only: Analyzes visible plaintext DNS on port 53.
     Encrypted DNS (DoH via RFC 8484 and DoT via RFC 7858) encapsulates queries
     in TLS and is NOT decrypted by this parser.
================================================================================
"""

import os
import re
import math
import struct
from collections import Counter
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

FEATURE_COLUMNS = [
    "FQDN_count",
    "subdomain_length",
    "upper",
    "lower",
    "numeric",
    "entropy",
    "special",
    "labels",
    "labels_max",
    "labels_average",
    "longest_word_len",
    "sld_len",
    "len",
    "subdomain"
]

TWO_PART_TLDS = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "gov.cn"
}

IPV6_EXT_HEADERS = {0, 43, 44, 51, 60}

# CIC-Bell-DNS-EXF-2021 special characters specification (dash, underscore, equal, space, tab)
# Note: '.' is a DNS label separator and is strictly NOT counted as a special character.
SPECIAL_CHARS = set("-_= \t")

# Supported PCAP / PCAPNG Link Layer Types
SUPPORTED_LINKTYPES = {
    0: "NULL_LOOPBACK",
    1: "ETHERNET",
    12: "RAW_IP",
    101: "RAW_IP",
    113: "LINUX_SLL",
    276: "LINUX_SLL2"
}

class NoDNSTrafficError(Exception):
    """Raised when the PCAP contains valid packets, but no usable DNS queries."""
    pass

class InvalidPCAPError(Exception):
    """Raised when the uploaded file cannot be parsed as a valid PCAP/PCAPNG."""
    pass

def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy for domain strings."""
    if not s:
        return 0.0
    cnt = Counter(s)
    n = len(s)
    return float(-sum((c / n) * math.log2(c / n) for c in cnt.values()))

def parse_domain_structure(clean_domain: str) -> Tuple[str, str, List[str]]:
    """
    Parses domain into (subdomain_str, sld_str, labels_list) using the documented
    NetSentinel domain parsing policy.
    """
    labels_list = [lbl for lbl in clean_domain.split(".") if lbl]
    num_labels = len(labels_list)

    if num_labels <= 1:
        return "", clean_domain, labels_list

    is_two_part = False
    if num_labels >= 3:
        potential_suffix = f"{labels_list[-2].lower()}.{labels_list[-1].lower()}"
        if potential_suffix in TWO_PART_TLDS:
            is_two_part = True

    if is_two_part:
        if num_labels >= 3:
            sld_str = labels_list[-3]
            subdomain_labels = labels_list[:-3]
        else:
            sld_str = labels_list[0]
            subdomain_labels = []
    else:
        sld_str = labels_list[-2]
        subdomain_labels = labels_list[:-2]

    subdomain_str = ".".join(subdomain_labels)
    return subdomain_str, sld_str, labels_list

def extract_features_from_domain(domain: str) -> Dict[str, Any]:
    """
    Computes the 14-feature live inference representation used by NetSentinel.
    """
    clean_domain = domain.strip().rstrip(".")
    if not clean_domain:
        return {col: 0 for col in FEATURE_COLUMNS}

    fqdn_count = len(clean_domain)
    upper = sum(1 for c in clean_domain if c.isupper())
    lower = sum(1 for c in clean_domain if c.islower())
    numeric = sum(1 for c in clean_domain if c.isdigit())
    special = sum(1 for c in clean_domain if c in SPECIAL_CHARS)
    entropy = calculate_shannon_entropy(clean_domain)

    subdomain_str, sld_str, labels_list = parse_domain_structure(clean_domain)

    num_labels = len(labels_list)
    labels_max = max((len(lbl) for lbl in labels_list), default=0)
    labels_avg = float(np.mean([len(lbl) for lbl in labels_list])) if labels_list else 0.0

    subdomain_len = len(subdomain_str)
    has_subdomain = 1 if subdomain_len > 0 else 0
    sld_len = len(sld_str)

    # Empirically verified against 757,211 rows in CIC dataset (100.00% match)
    computed_len = subdomain_len + sld_len + 1

    # Project-level engineered representation for longest_word
    tokens = re.findall(r"[A-Za-z0-9]+", clean_domain)
    longest_word_len = max((len(t) for t in tokens), default=0)

    return {
        "FQDN_count": fqdn_count,
        "subdomain_length": subdomain_len,
        "upper": upper,
        "lower": lower,
        "numeric": numeric,
        "entropy": entropy,
        "special": special,
        "labels": num_labels,
        "labels_max": labels_max,
        "labels_average": labels_avg,
        "longest_word_len": longest_word_len,
        "sld_len": sld_len,
        "len": computed_len,
        "subdomain": has_subdomain
    }

def _parse_dns_qname(payload: bytes, offset: int) -> Tuple[str, int]:
    """Decodes DNS query name with pointer decompression."""
    labels = []
    visited = set()
    orig_offset = offset
    jumped = False

    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(payload):
                break
            ptr = struct.unpack("!H", payload[offset:offset+2])[0] & 0x3FFF
            offset += 2
            if not jumped:
                orig_offset = offset
                jumped = True
            if ptr in visited or ptr >= len(payload):
                break
            visited.add(ptr)
            offset = ptr
        else:
            offset += 1
            if offset + length > len(payload):
                break
            label = payload[offset:offset+length].decode("utf-8", errors="replace")
            labels.append(label)
            offset += length

    final_offset = orig_offset if jumped else offset
    return ".".join(labels), final_offset

def _parse_dns_payload(dns_bytes: bytes) -> List[Dict[str, Any]]:
    """Extracts questions from DNS header/payload."""
    queries = []
    if len(dns_bytes) < 12:
        return queries

    try:
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_bytes[:12])
        # QR bit (bit 15 / 0x8000): 0 = Query, 1 = Response. Only process queries.
        if flags & 0x8000:
            return queries
        if qdcount == 0 or qdcount > 50:
            return queries

        offset = 12
        for _ in range(qdcount):
            if offset >= len(dns_bytes):
                break
            qname, offset = _parse_dns_qname(dns_bytes, offset)
            if offset + 4 <= len(dns_bytes):
                qtype, qclass = struct.unpack("!HH", dns_bytes[offset:offset+4])
                offset += 4
                if qname:
                    queries.append({
                        "query": qname,
                        "qtype": qtype,
                        "qclass": qclass
                    })
    except Exception:
        pass
    return queries

def _get_ip_offset_and_protocol(pkt_data: bytes, linktype: int) -> Tuple[int, int]:
    """
    Determines IP offset and EtherType/Address Family based on LinkType.
    Returns (ip_offset, ether_type).
    """
    if linktype == 1: # Ethernet
        if len(pkt_data) < 14:
            return -1, 0
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        # Handle 802.1Q VLAN tag
        if eth_type == 0x8100:
            if len(pkt_data) < 18:
                return -1, 0
            eth_type = struct.unpack("!H", pkt_data[16:18])[0]
            return 18, eth_type
        return 14, eth_type

    elif linktype in (12, 101): # Raw IP
        if len(pkt_data) < 1:
            return -1, 0
        v = (pkt_data[0] >> 4) & 0x0F
        if v == 4:
            return 0, 0x0800
        elif v == 6:
            return 0, 0x86DD
        return -1, 0

    elif linktype == 113: # Linux Cooked v1 (SLL)
        if len(pkt_data) < 16:
            return -1, 0
        eth_type = struct.unpack("!H", pkt_data[14:16])[0]
        return 16, eth_type

    elif linktype == 276: # Linux Cooked v2 (SLL2)
        if len(pkt_data) < 20:
            return -1, 0
        eth_type = struct.unpack("!H", pkt_data[0:2])[0]
        return 20, eth_type

    elif linktype == 0: # NULL / Loopback
        if len(pkt_data) < 4:
            return -1, 0
        # 4-byte family (often in host endianness)
        family_le = struct.unpack("<I", pkt_data[:4])[0]
        family_be = struct.unpack(">I", pkt_data[:4])[0]
        if family_le == 2 or family_be == 2: # AF_INET
            return 4, 0x0800
        elif family_le in (24, 28, 30) or family_be in (24, 28, 30): # AF_INET6
            return 4, 0x86DD
        return -1, 0

    return -1, 0

def _extract_transport_payload(ip_bytes: bytes, version: int) -> Tuple[int, bytes]:
    """
    Extracts transport protocol and payload from IPv4 or IPv6 packet bytes.
    Implements IPv6 extension-header traversal.
    Returns (protocol_number, transport_bytes).
    """
    if version == 4:
        if len(ip_bytes) < 20:
            return 0, b""
        ihl = (ip_bytes[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(ip_bytes):
            return 0, b""
        protocol = ip_bytes[9]
        return protocol, ip_bytes[ihl:]

    elif version == 6:
        if len(ip_bytes) < 40:
            return 0, b""
        next_hdr = ip_bytes[6]
        offset = 40

        while next_hdr in IPV6_EXT_HEADERS and offset < len(ip_bytes):
            if next_hdr == 44: # Fragment Header (fixed 8 bytes)
                if offset + 8 > len(ip_bytes):
                    return 0, b""
                next_hdr = ip_bytes[offset]
                offset += 8
            elif next_hdr == 51: # AH
                if offset + 2 > len(ip_bytes):
                    return 0, b""
                nh = ip_bytes[offset]
                payload_len = ip_bytes[offset + 1]
                hdr_len = (payload_len + 2) * 4
                next_hdr = nh
                offset += hdr_len
            else: # Hop-by-Hop, Routing, Destination Options
                if offset + 2 > len(ip_bytes):
                    return 0, b""
                nh = ip_bytes[offset]
                hdr_ext_len = ip_bytes[offset + 1]
                hdr_len = (hdr_ext_len + 1) * 8
                next_hdr = nh
                offset += hdr_len

        return next_hdr, ip_bytes[offset:]

    return 0, b""

def _extract_dns_from_transport(protocol: int, trans_bytes: bytes) -> Optional[bytes]:
    """
    Extracts DNS payload from UDP or single-segment TCP transport bytes.
    Note: Does not perform multi-segment TCP stream reassembly.
    """
    if protocol == 17: # UDP
        if len(trans_bytes) >= 8:
            src_port, dst_port, udp_len = struct.unpack("!HHH", trans_bytes[:6])
            if src_port == 53 or dst_port == 53:
                return trans_bytes[8:udp_len]

    elif protocol == 6: # TCP
        if len(trans_bytes) >= 20:
            src_port, dst_port = struct.unpack("!HH", trans_bytes[:4])
            data_offset = ((trans_bytes[12] >> 4) & 0x0F) * 4
            if data_offset < 20 or data_offset > len(trans_bytes):
                return None
            if src_port == 53 or dst_port == 53:
                tcp_data = trans_bytes[data_offset:]
                if len(tcp_data) >= 2:
                    dns_len = struct.unpack("!H", tcp_data[:2])[0]
                    if dns_len == 0 or len(tcp_data) < 2 + dns_len:
                        return None
                    return tcp_data[2:2+dns_len]

    return None

def _parse_native_pcap(filepath: str) -> Tuple[List[Tuple[float, str, int, int]], Dict[str, Any]]:
    """
    Native binary PCAP parser supporting both Little-Endian and Big-Endian captures.
    Returns (query_records, telemetry_metadata).
    """
    results = []
    telemetry = {
        "format": "PCAP",
        "endian": "unknown",
        "timestamp_resolution": "unknown",
        "linktype": -1,
        "packets_processed": 0,
        "dns_packets": 0
    }

    with open(filepath, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            raise InvalidPCAPError("File is too small to be a valid PCAP.")

        magic = struct.unpack("<I", global_header[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
            telemetry["endian"] = "Little-Endian"
            telemetry["timestamp_resolution"] = "microsecond"
            ts_divisor = 1e6
        elif magic == 0xA1B23C4D:
            endian = "<"
            telemetry["endian"] = "Little-Endian"
            telemetry["timestamp_resolution"] = "nanosecond"
            ts_divisor = 1e9
        elif magic == 0xD4C3B2A1:
            endian = ">"
            telemetry["endian"] = "Big-Endian"
            telemetry["timestamp_resolution"] = "microsecond"
            ts_divisor = 1e6
        elif magic == 0x4D3CB2A1:
            endian = ">"
            telemetry["endian"] = "Big-Endian"
            telemetry["timestamp_resolution"] = "nanosecond"
            ts_divisor = 1e9
        else:
            return [], telemetry

        linktype = struct.unpack(f"{endian}I", global_header[20:24])[0]
        telemetry["linktype"] = linktype

        if linktype not in SUPPORTED_LINKTYPES:
            print(f"Warning: Unsupported PCAP linktype {linktype}. Only standard network linktypes supported.")
            return [], telemetry

        packet_index = 0
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            packet_index += 1
            telemetry["packets_processed"] += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            ts = float(ts_sec) + (float(ts_usec) / ts_divisor)

            ip_offset, eth_type = _get_ip_offset_and_protocol(pkt_data, linktype)
            if ip_offset < 0 or len(pkt_data) <= ip_offset:
                continue

            ip_bytes = pkt_data[ip_offset:]
            if len(ip_bytes) < 20:
                continue

            version = (ip_bytes[0] >> 4) & 0x0F
            if version not in (4, 6):
                continue

            protocol, trans_bytes = _extract_transport_payload(ip_bytes, version)
            dns_payload = _extract_dns_from_transport(protocol, trans_bytes)

            if dns_payload:
                telemetry["dns_packets"] += 1
                for q in _parse_dns_payload(dns_payload):
                    results.append((ts, q["query"], q["qtype"], packet_index))

    return results, telemetry

def _parse_idb_options(options_bytes: bytes, endian: str) -> Dict[str, Any]:
    """Parses Interface Description Block (IDB) options, including if_tsresol."""
    opts = {"tsresol_scale": 1e-6} # default is 10^-6 (microseconds)
    offset = 0
    while offset + 4 <= len(options_bytes):
        opt_code, opt_len = struct.unpack(f"{endian}HH", options_bytes[offset:offset+4])
        offset += 4
        if opt_code == 0: # opt_endofopt
            break
        if offset + opt_len > len(options_bytes):
            break
        opt_val = options_bytes[offset:offset+opt_len]
        # Align to 4-byte boundary
        pad = (4 - (opt_len % 4)) % 4
        offset += opt_len + pad

        if opt_code == 9 and len(opt_val) >= 1: # if_tsresol
            raw_res = opt_val[0]
            is_binary = bool(raw_res & 0x80)
            power = raw_res & 0x7F
            if is_binary:
                opts["tsresol_scale"] = 1.0 / (2 ** power)
            else:
                opts["tsresol_scale"] = 1.0 / (10 ** power)

    return opts

def _parse_native_pcapng(filepath: str) -> Tuple[List[Tuple[float, str, int, int]], Dict[str, Any]]:
    """
    Extracts DNS queries from PCAPNG files conforming to the PCAPNG specification.
    - Section Header Block (SHB, 0x0A0D0D0A):
      * Byte-Order Magic detection (0x1A2B3C4D: Little-Endian '<', Big-Endian '>').
      * Multi-section support: resets interface table and re-detects byte order per section.
    - Interface Description Block (IDB, 0x00000001):
      * Extracts LinkType, SnapLen, and parses options including 'if_tsresol' (Option 9)
        for custom timestamp resolution (powers of 10 or powers of 2).
    - Enhanced Packet Block (EPB, 0x00000006):
      * Layout:
          0-3:   Interface ID
          4-7:   Timestamp High
          8-11:  Timestamp Low
          12-15: Captured Packet Length (cap_len)
          16-19: Original Packet Length (orig_len)
          20+:   Packet Data (cap_len bytes)
      * 32-bit packet data alignment/padding validation.
      * Bounds validation before slicing packet data at offset 20.
      * Interface ID -> LinkType lookup. Unsupported linktypes are explicitly skipped and logged.
    - Simple Packet Block (SPB, 0x00000003):
      * SPBs do not carry timestamp or interface ID; explicitly unsupported and skipped.
    Returns (query_records, telemetry_metadata).
    """
    results = []
    telemetry = {
        "format": "PCAPNG",
        "endian": "unknown",
        "sections": 0,
        "interfaces": [],
        "unsupported_linktypes": [],
        "packets_processed": 0,
        "dns_packets": 0
    }

    with open(filepath, "rb") as f:
        # Initial check for PCAPNG magic (0x0A0D0D0A is palindromic in byte order)
        header = f.read(4)
        if len(header) < 4 or header != b"\x0a\x0d\x0d\x0a":
            return [], telemetry

        f.seek(0)
        packet_idx = 0
        interfaces = []
        endian = "<" # default fallback until detected from SHB BOM

        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break

            # 1. Section Header Block (SHB, 0x0A0D0D0A)
            # Both 0x0A0D0D0A and byte sequence \x0a\x0d\x0d\x0a are identical regardless of endianness.
            if block_hdr[:4] == b"\x0a\x0d\x0d\x0a":
                telemetry["sections"] += 1
                interfaces = [] # Interface IDs reset per section as per PCAPNG specification

                # Read Byte-Order Magic (BOM) at offset 8..11
                bom = f.read(4)
                if len(bom) < 4:
                    break
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                    telemetry["endian"] = "Little-Endian"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                    telemetry["endian"] = "Big-Endian"
                else:
                    break # Corrupted / unknown Byte-Order Magic

                # Now unpack block_len using the section's detected endianness
                block_len = struct.unpack(f"{endian}I", block_hdr[4:8])[0]
                if block_len < 16 or (block_len % 4) != 0:
                    break

                body_len = block_len - 12 # minus type[4] + len[4] + trailing_len[4]
                # We already consumed 4 bytes (the BOM) from the body
                rem_body = f.read(body_len - 4)
                trailing_len_bytes = f.read(4)
                if len(rem_body) < body_len - 4 or len(trailing_len_bytes) < 4:
                    break

                trailing_len = struct.unpack(f"{endian}I", trailing_len_bytes)[0]
                if trailing_len != block_len:
                    break # Block length mismatch / corruption
                continue

            # Unpack non-SHB block headers using current section endianness
            block_type, block_len = struct.unpack(f"{endian}II", block_hdr)
            if block_len < 12 or (block_len % 4) != 0:
                break # Invalid block length

            body_len = block_len - 12
            block_body = f.read(body_len)
            trailing_len_bytes = f.read(4)

            if len(block_body) < body_len or len(trailing_len_bytes) < 4:
                break

            trailing_len = struct.unpack(f"{endian}I", trailing_len_bytes)[0]
            if trailing_len != block_len:
                break # Block corruption / misalignment

            # 2. Interface Description Block (IDB, 0x00000001)
            if block_type == 1:
                if len(block_body) >= 8:
                    linktype, reserved, snaplen = struct.unpack(f"{endian}HHI", block_body[:8])
                    options_bytes = block_body[8:]
                    opts = _parse_idb_options(options_bytes, endian)
                    intf_meta = {
                        "id": len(interfaces),
                        "linktype": linktype,
                        "linktype_name": SUPPORTED_LINKTYPES.get(linktype, f"UNSUPPORTED_{linktype}"),
                        "snaplen": snaplen,
                        "tsresol_scale": opts["tsresol_scale"]
                    }
                    interfaces.append(intf_meta)
                    telemetry["interfaces"].append(intf_meta)

            # 3. Simple Packet Block (SPB, 0x00000003)
            elif block_type == 3:
                # SPBs do not carry timestamp or interface ID; explicitly unsupported and skipped
                continue

            # 4. Enhanced Packet Block (EPB, 0x00000006)
            elif block_type == 6:
                # EPB Body Layout:
                #   0-3:   Interface ID
                #   4-7:   Timestamp High
                #   8-11:  Timestamp Low
                #   12-15: Captured Packet Length (cap_len)
                #   16-19: Original Packet Length (orig_len)
                #   20+:   Packet Data (cap_len bytes, padded to 32-bit boundary)
                if len(block_body) < 20:
                    continue

                intf_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    f"{endian}IIIII", block_body[:20]
                )

                # Strict bounds and 32-bit alignment validation
                pad = (4 - (cap_len % 4)) % 4
                if len(block_body) < 20 + cap_len + pad:
                    continue

                packet_idx += 1
                telemetry["packets_processed"] += 1

                # Look up Interface ID to get LinkType & Time Resolution
                if intf_id >= len(interfaces):
                    continue
                intf = interfaces[intf_id]
                linktype = intf["linktype"]

                if linktype not in SUPPORTED_LINKTYPES:
                    if linktype not in telemetry["unsupported_linktypes"]:
                        telemetry["unsupported_linktypes"].append(linktype)
                    continue # Explicitly skip unsupported linktypes

                # Compute timestamp with interface-specific resolution
                ts_ticks = (ts_high << 32) | ts_low
                ts = float(ts_ticks) * intf["tsresol_scale"]

                # Packet data begins at offset 20
                pkt_data = block_body[20:20+cap_len]

                # Parse layer 3 offset and protocol based on interface linktype
                ip_offset, eth_type = _get_ip_offset_and_protocol(pkt_data, linktype)
                if ip_offset < 0 or len(pkt_data) <= ip_offset:
                    continue

                ip_bytes = pkt_data[ip_offset:]
                if len(ip_bytes) < 20:
                    continue

                version = (ip_bytes[0] >> 4) & 0x0F
                if version not in (4, 6):
                    continue

                protocol, trans_bytes = _extract_transport_payload(ip_bytes, version)
                dns_payload = _extract_dns_from_transport(protocol, trans_bytes)

                if dns_payload:
                    telemetry["dns_packets"] += 1
                    for q in _parse_dns_payload(dns_payload):
                        results.append((ts, q["query"], q["qtype"], packet_idx))

    return results, telemetry

def extract_dns_with_telemetry(filepath: str) -> Tuple[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extracts DNS queries and returns:
      - DataFrame of features strictly matching FEATURE_COLUMNS
      - List of query metadata records
      - Comprehensive parser telemetry dictionary
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    if os.path.getsize(filepath) == 0:
        raise InvalidPCAPError("The uploaded file is empty (0 bytes).")

    with open(filepath, "rb") as f:
        magic_head = f.read(4)

    is_pcap = (magic_head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"))
    is_pcapng = (magic_head == b"\x0a\x0d\x0d\x0a")

    if not is_pcap and not is_pcapng:
        raise InvalidPCAPError("Uploaded file is not a valid PCAP or PCAPNG packet capture.")

    raw_queries = []
    telemetry = {}

    if is_pcapng:
        raw_queries, telemetry = _parse_native_pcapng(filepath)
    else:
        raw_queries, telemetry = _parse_native_pcap(filepath)

    if not raw_queries:
        raise NoDNSTrafficError("No usable DNS traffic was found in this PCAP.")

    features_list = []
    query_records = []

    for item in raw_queries:
        ts, qname, qtype, pkt_idx = item
        clean_q = qname.strip().rstrip(".")
        if len(clean_q) < 2:
            continue

        feat = extract_features_from_domain(clean_q)
        features_list.append(feat)
        query_records.append({
            "packet_index": pkt_idx,
            "query": clean_q,
            "qtype": qtype,
            "timestamp": ts,
            "features": feat
        })

    if not features_list:
        raise NoDNSTrafficError("No usable DNS traffic was found in this PCAP.")

    feature_df = pd.DataFrame(features_list)[FEATURE_COLUMNS]
    return feature_df, query_records, telemetry

def extract_dns_from_pcap(filepath: str) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """
    Main extraction interface for backward compatibility.
    Returns (feature_df, query_records).
    """
    df, records, _ = extract_dns_with_telemetry(filepath)
    return df, records
