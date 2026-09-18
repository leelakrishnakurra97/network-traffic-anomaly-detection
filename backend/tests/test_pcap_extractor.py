"""
Automated unit tests for PCAP extraction and DNS feature engineering.
"""

import os
import pytest
from backend.app.dns.pcap_extractor import (
    extract_dns_from_pcap,
    extract_features_from_domain,
    calculate_shannon_entropy,
    NoDNSTrafficError,
    InvalidPCAPError,
    FEATURE_COLUMNS
)

def test_feature_extraction_from_domain():
    domain = "www.google.com"
    feats = extract_features_from_domain(domain)
    assert set(feats.keys()) == set(FEATURE_COLUMNS)
    assert feats["FQDN_count"] == 14
    assert feats["labels"] == 3
    assert feats["subdomain"] == 1
    assert feats["subdomain_length"] == 3
    assert feats["sld_len"] == 6 # "google"
    assert feats["entropy"] > 0.0

def test_shannon_entropy():
    # Repeating string has low entropy
    low_ent = calculate_shannon_entropy("aaaaaaa")
    assert low_ent == 0.0

    # Mixed diverse string has higher entropy
    high_ent = calculate_shannon_entropy("a1b2c3d4e5f6g7h8")
    assert high_ent > 3.5

def test_benign_pcap_extraction():
    pcap_path = "uploads/sample_pcaps/benign_dns_traffic.pcap"
    if os.path.exists(pcap_path):
        df, recs = extract_dns_from_pcap(pcap_path)
        assert len(recs) == 5
        assert list(df.columns) == FEATURE_COLUMNS
        assert df.shape[0] == 5

def test_non_dns_pcap_raises_no_dns_error():
    pcap_path = "uploads/sample_pcaps/non_dns_traffic.pcap"
    if os.path.exists(pcap_path):
        with pytest.raises(NoDNSTrafficError) as exc_info:
            extract_dns_from_pcap(pcap_path)
        assert "No usable DNS traffic was found" in str(exc_info.value)

def test_corrupt_pcap_raises_invalid_pcap_error():
    pcap_path = "uploads/sample_pcaps/corrupt_file.pcap"
    if os.path.exists(pcap_path):
        with pytest.raises(InvalidPCAPError) as exc_info:
            extract_dns_from_pcap(pcap_path)
        assert "not a valid PCAP" in str(exc_info.value)

def test_wireshark_pcapng_extraction():
    pcapng_path = "uploads/sample_pcaps/wireshark_dns_sample.pcapng"
    if os.path.exists(pcapng_path):
        df, recs = extract_dns_from_pcap(pcapng_path)
        assert len(recs) == 5
        assert list(df.columns) == FEATURE_COLUMNS
        assert df.shape[0] == 5
        queries = [r["query"] for r in recs]
        assert "www.google.com" in queries
        assert "mail.google.com" in queries

def test_special_character_specification():
    # Dots must NOT be counted as special; only -_= \t are special
    assert extract_features_from_domain("www.google.com")["special"] == 0
    assert extract_features_from_domain("abc-def.google.com")["special"] == 1
    assert extract_features_from_domain("abc_def.google.com")["special"] == 1
    assert extract_features_from_domain("abc=def.google.com")["special"] == 1

def test_dns_query_response_filtering():
    import struct
    from backend.app.dns.pcap_extractor import _parse_dns_payload

    def make_dns_packet(flags: int, qname: str = "example.com"):
        hdr = struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0)
        qbody = b""
        for part in qname.split("."):
            qbody += bytes([len(part)]) + part.encode()
        qbody += b"\x00" + struct.pack("!HH", 1, 1)
        return hdr + qbody

    # Query (QR=0, e.g. flags=0x0100)
    query_pkt = make_dns_packet(0x0100)
    assert len(_parse_dns_payload(query_pkt)) == 1

    # Response (QR=1, e.g. flags=0x8180)
    response_pkt = make_dns_packet(0x8180)
    assert len(_parse_dns_payload(response_pkt)) == 0

def test_tcp_and_ipv4_bounds_hardening():
    import struct
    from backend.app.dns.pcap_extractor import _extract_transport_payload, _extract_dns_from_transport

    # IPv4 IHL out of bounds
    ip_bad_ihl = bytes([0x44, 0x00, 0x00, 0x28]) + b"\x00" * 36 # ihl = 16 < 20
    proto, pay = _extract_transport_payload(ip_bad_ihl, 4)
    assert proto == 0 and pay == b""

    # TCP data_offset out of bounds (< 20)
    tcp_bad_offset = struct.pack("!HH", 53, 1234) + b"\x00" * 8 + bytes([0x30, 0x00]) + b"\x00" * 6
    assert _extract_dns_from_transport(6, tcp_bad_offset) is None

    # TCP declared length exceeds available bytes
    tcp_short = struct.pack("!HH", 53, 1234) + b"\x00" * 8 + bytes([0x50, 0x00]) + b"\x00" * 6 + struct.pack("!H", 50) + b"abc"
    assert _extract_dns_from_transport(6, tcp_short) is None

def test_classic_pcap_timestamp_resolutions(tmp_path):
    import struct
    from backend.app.dns.pcap_extractor import _parse_native_pcap, extract_dns_with_telemetry

    def build_test_pcap(magic_bytes: bytes, ts_sec: int, ts_frac: int, endian: str = "<") -> bytes:
        gh = magic_bytes + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, 1)
        qbody = b"\x03www\x06google\x03com\x00\x00\x01\x00\x01"
        dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qbody
        udp = struct.pack("!HHHH", 1234, 53, 8 + len(dns), 0) + dns
        ip = bytes([0x45, 0, 0, 20 + len(udp), 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8]) + udp
        eth = b"\x00" * 12 + b"\x08\x00" + ip
        ph = struct.pack(f"{endian}IIII", ts_sec, ts_frac, len(eth), len(eth))
        return gh + ph + eth

    # 1. Microsecond PCAP (0xA1B2C3D4, Little-Endian, ts_frac=500,000 -> 0.5s)
    pcap_usec_file = tmp_path / "usec.pcap"
    pcap_usec_file.write_bytes(build_test_pcap(b"\xd4\xc3\xb2\xa1", 1700000000, 500000, "<"))
    df_u, recs_u, tel_u = extract_dns_with_telemetry(str(pcap_usec_file))
    assert tel_u["timestamp_resolution"] == "microsecond"
    assert tel_u["endian"] == "Little-Endian"
    assert abs(recs_u[0]["timestamp"] - 1700000000.5) < 1e-6

    # 2. Nanosecond PCAP (0xA1B23C4D, Little-Endian, ts_frac=500,000,000 -> 0.5s)
    pcap_nsec_file = tmp_path / "nsec.pcap"
    pcap_nsec_file.write_bytes(build_test_pcap(b"\x4d\x3c\xb2\xa1", 1700000000, 500000000, "<"))
    df_n, recs_n, tel_n = extract_dns_with_telemetry(str(pcap_nsec_file))
    assert tel_n["timestamp_resolution"] == "nanosecond"
    assert tel_n["endian"] == "Little-Endian"
    assert abs(recs_n[0]["timestamp"] - 1700000000.5) < 1e-6

    # 3. Nanosecond PCAP Big-Endian (0x4D3CB2A1, Big-Endian)
    pcap_nsec_be_file = tmp_path / "nsec_be.pcap"
    pcap_nsec_be_file.write_bytes(build_test_pcap(b"\xa1\xb2\x3c\x4d", 1700000000, 500000000, ">"))
    df_nb, recs_nb, tel_nb = extract_dns_with_telemetry(str(pcap_nsec_be_file))
    assert tel_nb["timestamp_resolution"] == "nanosecond"
    assert tel_nb["endian"] == "Big-Endian"
    assert abs(recs_nb[0]["timestamp"] - 1700000000.5) < 1e-6
