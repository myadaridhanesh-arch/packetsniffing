"""Offline classic-PCAP reader and optional, explicitly enabled Scapy live capture."""
import struct
import time

def read_pcap(path):
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) != 24:
            raise ValueError("File is too small to be a PCAP file")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }
        if magic not in formats:
            raise ValueError("Unsupported PCAP format (classic PCAP expected)")
        endian, divisor = formats[magic]
        _, _, _, _, _, network = struct.unpack(endian + "HHIIII", header[4:])
        if network != 1:
            raise ValueError("Only Ethernet-link PCAP files are supported")
        while True:
            packet_header = f.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Truncated PCAP packet header")
            sec, fraction, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            frame = f.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError("Truncated PCAP packet data")
            yield frame, sec + fraction / divisor

def live_frames(interface=None, count=0):
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Live mode needs Scapy. Install with: pip install scapy") from exc
    seen = []
    def collect(pkt):
        seen.append((bytes(pkt), float(pkt.time)))
    sniff(iface=interface, prn=collect, store=False, count=count or 0, timeout=10)
    yield from seen
