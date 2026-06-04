"""GoPay SSL流量持续捕获"""
import frida
import time
import os
import sys
import json
import struct

WORKDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(WORKDIR, "frida", "gopay_ssl_capture_full.js")
LOG = os.path.join(WORKDIR, "captures", "ssl_traffic.log")
BIN_LOG = os.path.join(WORKDIR, "captures", "ssl_dump.bin")

# ========== 配置区 ==========
# 填写你手机的 Frida Server 地址和端口
FRIDA_DEVICE = "192.168.x.x:27042"
# ============================

device = frida.get_device_manager().add_remote_device(FRIDA_DEVICE)

# Find GoPay (process name may be "Gojek" or "com.gojek.gopay")
target_pid = None
for p in device.enumerate_processes():
    name_lower = p.name.lower()
    if ("gopay" in name_lower or "gojek" in name_lower) and "notification" not in name_lower:
        target_pid = p.pid
        print(f"    Found: {p.name} (PID={p.pid})")
        break

if not target_pid:
    print("[!] GoPay not found")
    sys.exit(1)

print(f"[*] GoPay PID={target_pid}")
session = device.attach(target_pid)

with open(SCRIPT, "r", encoding="utf-8") as f:
    script_code = f.read()

os.makedirs(os.path.join(WORKDIR, "captures"), exist_ok=True)
logfile = open(LOG, "w", encoding="utf-8")
binfile = open(BIN_LOG, "wb")

packet_count = 0
protobuf_packets = []

def on_message(msg, data):
    global packet_count
    if msg["type"] == "send":
        payload = msg["payload"]
        ts = time.strftime("%H:%M:%S")

        if isinstance(payload, dict) and "t" in payload:
            # SSL capture data
            direction = ">>>" if payload["t"] == "w" else "<<<"
            size = payload.get("s", 0)
            seq = payload.get("seq", 0)

            # Try to decode as text
            text_repr = ""
            if data:
                try:
                    text = data.decode("utf-8", errors="replace")
                    readable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
                    if readable > len(text) * 0.3:
                        text_repr = text[:500]
                except:
                    pass

            # Check for protobuf markers
            is_protobuf = False
            if data and len(data) > 10:
                if data[0] in (0x0a, 0x12, 0x1a, 0x22, 0x2a, 0x32):
                    is_protobuf = True
                    protobuf_packets.append({
                        "seq": seq,
                        "dir": direction,
                        "size": size,
                        "data": data.hex()[:200],
                        "text": text_repr[:200]
                    })

            line = f"{ts} {direction} seq={seq} size={size}"
            if text_repr:
                line += f" text={text_repr[:100]}"
            if is_protobuf:
                line += " [PROTOBUF]"

            print(line)
            logfile.write(line + "\n")
            logfile.flush()

            # Save binary data
            if data:
                binfile.write(struct.pack(">I", len(data)))
                binfile.write(data)
                binfile.flush()

            packet_count += 1

        elif isinstance(payload, str):
            # Status messages
            print(f"  {payload}")
            logfile.write(f"{ts} {payload}\n")
            logfile.flush()

    elif msg["type"] == "error":
        print(f"[ERR] {msg}")

script = session.create_script(script_code)
script.on("message", on_message)
script.load()

print(f"[*] SSL capture active — {LOG}")
print("[*] 在GoPay上操作登录，Ctrl+C停止\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n[*] 捕获了 {packet_count} 个SSL包")
    print(f"[*] 其中 {len(protobuf_packets)} 个可能是protobuf")

    # Save protobuf analysis
    if protobuf_packets:
        with open(os.path.join(WORKDIR, "captures", "protobuf_packets.json"), "w") as f:
            json.dump(protobuf_packets, f, indent=2, ensure_ascii=False)
        print(f"[*] Protobuf包已保存: captures/protobuf_packets.json")

    logfile.close()
    binfile.close()
    session.detach()
    print("[*] Done")
