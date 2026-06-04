#!/usr/bin/env python3
"""GoPay SSL 抓包 PC 端 —— 雷电模拟器 / 通用版。

配合同目录 ``ld_capture.js``（按符号自动定位 SSL_read/SSL_write，不靠硬编
偏移）。把 GoPay 的明文 HTTP 请求/响应实时打印 + 落盘，专门用来抓
"Linked Apps 解绑 OpenAI LLC" 那条请求。

用法（先按教程起好 frida-server 并 adb forward 端口）：
    python ld_capture.py                 # 默认连 127.0.0.1:19876
    python ld_capture.py --host 127.0.0.1:27042
    python ld_capture.py --spawn         # 由 frida 拉起 GoPay（而不是 attach 已运行的）

抓完 Ctrl+C 停止。结果：
    captures/ld_traffic.log   —— 人类可读的请求/响应流水（重点看这个）
    captures/ld_requests.jsonl —— 每条解析出的 HTTP 请求（结构化，便于贴回来）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

try:
    import frida
except ImportError:
    print("[!] 没装 frida。先运行: pip install frida-tools==14.8.2 frida==17.9.11")
    sys.exit(1)

WORKDIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(WORKDIR, "ld_capture.js")
CAP_DIR = os.path.join(WORKDIR, "captures")
LOG = os.path.join(CAP_DIR, "ld_traffic.log")
REQ_JSONL = os.path.join(CAP_DIR, "ld_requests.jsonl")

PKG = "com.gojek.gopay"

# 解绑相关关键词：命中就在日志里高亮（★），方便你一眼找到那条
HILITE = re.compile(
    r"linked|unlink|de-?link|connected|consent|revoke|merchant|"
    r"authoriz|deregister|disconnect|/v\d+/.*account|tertaut|aplikasi|"
    r"autopay|mandate|partner",
    re.I,
)


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _looks_http(text: str) -> bool:
    if not text:
        return False
    head = text[:16].upper()
    return (
        head.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "))
        or head.startswith("HTTP/")
    )


def _summarize_request(text: str) -> dict | None:
    """从明文 HTTP 请求里抽 method/path/host/body。非 HTTP 返回 None。"""
    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", text)
    if not m:
        return None
    method, path = m.group(1), m.group(2)
    host = ""
    hm = re.search(r"^[Hh]ost:\s*(\S+)", text, re.M)
    if hm:
        host = hm.group(1).strip()
    body = ""
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]
    elif "\n\n" in text:
        body = text.split("\n\n", 1)[1]
    return {"method": method, "host": host, "path": path, "body": body[:4000]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:19876", help="frida-server 地址:端口")
    ap.add_argument("--spawn", action="store_true", help="由 frida 拉起 GoPay（默认 attach 已运行进程）")
    args = ap.parse_args()

    os.makedirs(CAP_DIR, exist_ok=True)
    with open(SCRIPT, "r", encoding="utf-8") as f:
        script_code = f.read()

    print(f"[*] 连接 frida-server @ {args.host} …")
    device = frida.get_device_manager().add_remote_device(args.host)

    if args.spawn:
        print(f"[*] spawn {PKG} …")
        pid = device.spawn([PKG])
        session = device.attach(pid)
    else:
        target_pid = None
        for p in device.enumerate_processes():
            nl = p.name.lower()
            if ("gopay" in nl or "gojek" in nl) and "notification" not in nl:
                target_pid = p.pid
                print(f"    找到: {p.name} (PID={p.pid})")
                break
        if not target_pid:
            print("[!] 没找到 GoPay 进程。先在雷电里手动打开 GoPay，或用 --spawn。")
            return 1
        session = device.attach(target_pid)

    logfile = open(LOG, "w", encoding="utf-8")
    reqfile = open(REQ_JSONL, "w", encoding="utf-8")
    stats = {"pkt": 0, "req": 0, "hi": 0}

    def on_message(msg, data):
        if msg.get("type") == "error":
            print(f"[ERR] {msg.get('description') or msg}")
            return
        if msg.get("type") != "send":
            return
        payload = msg["payload"]
        ts = time.strftime("%H:%M:%S")

        # 状态/日志字符串
        if isinstance(payload, str):
            print(f"  {payload}")
            logfile.write(f"{ts} {payload}\n")
            logfile.flush()
            return

        # SSL 数据包
        if isinstance(payload, dict) and "t" in payload:
            stats["pkt"] += 1
            direction = ">>>(发)" if payload["t"] == "w" else "<<<(收)"
            size = payload.get("s", 0)
            text = _decode(data) if data else ""

            req = _summarize_request(text) if payload["t"] == "w" else None
            if req:
                stats["req"] += 1
                line = f"{ts} {direction} {req['method']} {req['host']}{req['path']} (len={size})"
                hot = bool(HILITE.search(req["path"]) or HILITE.search(req["host"]))
                if hot:
                    stats["hi"] += 1
                    line = "★ " + line
                print(line)
                if req["body"]:
                    print(f"      body: {req['body'][:300]}")
                logfile.write(line + "\n")
                if req["body"]:
                    logfile.write(f"      body: {req['body']}\n")
                logfile.flush()
                reqfile.write(json.dumps({"ts": ts, "hot": hot, **req}, ensure_ascii=False) + "\n")
                reqfile.flush()
            else:
                # 响应或非 HTTP 分片：命中关键词才打印（响应体里也可能有 OpenAI/merchant）
                snippet = text[:300].replace("\n", " ").replace("\r", "")
                if _looks_http(text) or HILITE.search(text or ""):
                    mark = "★ " if HILITE.search(text or "") else ""
                    line = f"{ts} {mark}{direction} (len={size}) {snippet}"
                    print(line)
                    logfile.write(line + "\n")
                    logfile.flush()

    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    if args.spawn:
        device.resume(session._impl.pid if hasattr(session, "_impl") else None)

    print("\n[*] 抓包已启动。现在在雷电的 GoPay 里操作：")
    print("    我的/账户 → 已连接的应用(Aplikasi Tertaut/Linked apps) → OpenAI LLC → 解绑")
    print("[*] 带 ★ 的就是疑似解绑请求。Ctrl+C 停止。\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[*] 抓到 {stats['pkt']} 个 SSL 包，其中 {stats['req']} 条 HTTP 请求，"
              f"{stats['hi']} 条命中解绑关键词(★)")
        print(f"[*] 流水日志: {LOG}")
        print(f"[*] 结构化请求: {REQ_JSONL}")
        try:
            script.unload()
        except Exception:
            pass
        session.detach()
        logfile.close()
        reqfile.close()
        print("[*] Done。把 ld_traffic.log 里带 ★ 的那几条（含 body）贴回来即可。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
