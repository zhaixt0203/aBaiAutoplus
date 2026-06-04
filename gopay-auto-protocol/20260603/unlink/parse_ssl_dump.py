"""解析SSL dump二进制文件，提取明文HTTP请求/响应"""
import struct
import sys
import os


def packet_from_payload(direction, ts_ms, ssl_hex, payload):
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    is_http = False
    http_text = ""
    if text:
        if text.startswith(("POST ", "GET ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")):
            is_http = True
            http_text = text
        elif text.startswith("HTTP/1."):
            is_http = True
            http_text = text
        elif text.startswith("{") or text.startswith("["):
            is_http = True
            http_text = text

    if direction == "W":
        dir_label = ">>>"
    elif direction == "R":
        dir_label = "<<<"
    else:
        dir_label = "???"

    return {
        "dir": dir_label,
        "ts": ts_ms,
        "ssl": ssl_hex,
        "size": len(payload),
        "is_http": is_http,
        "text": http_text[:2000] if http_text else text[:200],
        "raw": payload
    }


def parse_tlsx_records(data):
    offset = 0
    packets = []
    while offset < len(data) - 33:
        magic = data[offset:offset+4]
        if magic != b"TLSx":
            offset += 1
            continue

        direction = chr(data[offset+4])  # 'R' or 'W'
        ts_ms = struct.unpack("<Q", data[offset+5:offset+13])[0]
        ssl_hex = data[offset+13:offset+29].decode("ascii", errors="replace")
        payload_len = struct.unpack("<I", data[offset+29:offset+33])[0]

        offset += 33
        if offset + payload_len > len(data):
            break

        payload = data[offset:offset+payload_len]
        offset += payload_len
        packets.append(packet_from_payload(direction, ts_ms, ssl_hex, payload))

    return packets


def parse_legacy_length_records(data):
    """Parse old host-side dump: 4-byte big-endian length + payload."""
    offset = 0
    packets = []
    while offset + 4 <= len(data):
        payload_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4

        if payload_len <= 0 or offset + payload_len > len(data):
            return []

        payload = data[offset:offset+payload_len]
        offset += payload_len
        packets.append(packet_from_payload("?", None, "", payload))

    return packets


def parse_ssl_dump(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    packets = parse_tlsx_records(data)
    if packets:
        return packets

    return parse_legacy_length_records(data)


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "ssl_dump_device.bin"
    packets = parse_ssl_dump(filepath)

    print(f"解析了 {len(packets)} 个SSL包\n")

    # Print HTTP packets
    for i, pkt in enumerate(packets):
        if pkt["is_http"]:
            print(f"{'='*60}")
            print(f"[{i}] {pkt['dir']} size={pkt['size']}")
            print(pkt["text"][:1000])
            print()

    # Save all packets
    out = filepath.replace(".bin", "_parsed.txt")
    with open(out, "w", encoding="utf-8") as f:
        for i, pkt in enumerate(packets):
            f.write(f"{'='*60}\n")
            f.write(f"[{i}] {pkt['dir']} size={pkt['size']} http={pkt['is_http']}\n")
            if pkt["text"]:
                f.write(pkt["text"][:3000] + "\n")
            f.write("\n")
    print(f"完整解析保存到: {out}")

    # Extract just HTTP requests
    http_out = filepath.replace(".bin", "_http.txt")
    with open(http_out, "w", encoding="utf-8") as f:
        for i, pkt in enumerate(packets):
            if pkt["is_http"] and pkt["text"]:
                f.write(f"{'='*60}\n")
                f.write(f"[{i}] {pkt['dir']} size={pkt['size']}\n")
                f.write(pkt["text"][:5000] + "\n\n")
    print(f"HTTP请求保存到: {http_out}")
