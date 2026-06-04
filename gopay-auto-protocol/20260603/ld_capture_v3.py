#!/usr/bin/env python3
"""GoPay 抓包 PC 端 v3 —— 配合 ld_capture_okhttp.js（Java OkHttp + native 兜底）。

v2 只抓到 AppsFlyer 统计，业务流量不经过系统 libssl。v3 直接 hook Java 层
OkHttp 的拦截链，拿到明文 Request/Response（含 URL/method/header/body），
专门揪 "Linked Apps 解绑 OpenAI" 那条。

用法：
    python ld_capture_v3.py --host 127.0.0.1:19876
解绑操作走完 Ctrl+C 停止。结果：
    captures/ld_v3_traffic.log    —— 人读流水（Java 请求/响应 + native 兜底）
    captures/ld_v3_requests.jsonl —— 每条 Java 请求/响应结构化
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
    print("[!] 没装 frida：pip install frida==17.9.11")
    sys.exit(1)

WORKDIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(WORKDIR, "ld_capture_okhttp.js")
CAP_DIR = os.path.join(WORKDIR, "captures")
LOG = os.path.join(CAP_DIR, "ld_v3_traffic.log")
REQ_JSONL = os.path.join(CAP_DIR, "ld_v3_requests.jsonl")

HILITE = re.compile(
    r"linked|unlink|de-?link|connected|consent|revoke|merchant|"
    r"authoriz|deregister|disconnect|tertaut|aplikasi|autopay|mandate|"
    r"openai|partner|/v\d+/.*account",
    re.I,
)


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:19876")
    args = ap.parse_args()

    os.makedirs(CAP_DIR, exist_ok=True)
    with open(SCRIPT, "r", encoding="utf-8") as f:
        code = f.read()

    device = frida.get_device_manager().add_remote_device(args.host)
    pid = None
    for p in device.enumerate_processes():
        nl = p.name.lower()
        if ("gopay" in nl or "gojek" in nl) and "notification" not in nl:
            pid = p.pid
            print(f"[*] attach {p.name} (PID={p.pid})")
            break
    if not pid:
        print("[!] 没找到 GoPay，先在雷电打开 GoPay")
        return 1

    session = device.attach(pid)
    logf = open(LOG, "w", encoding="utf-8")
    reqf = open(REQ_JSONL, "w", encoding="utf-8")
    stats = {"java_req": 0, "java_resp": 0, "native": 0, "hot": 0}

    def on_message(msg, data):
        if msg.get("type") == "error":
            print(f"[ERR] {msg.get('description') or msg}")
            return
        if msg.get("type") != "send":
            return
        payload = msg["payload"]
        ts = time.strftime("%H:%M:%S")

        if isinstance(payload, str):
            print("  " + payload)
            logf.write(f"{ts} {payload}\n"); logf.flush()
            return

        # Java 层结构化请求/响应
        if isinstance(payload, dict) and payload.get("java"):
            d = payload.get("dir")
            url = payload.get("url", "")
            hot = bool(HILITE.search(url) or HILITE.search(payload.get("body", "") or ""))
            if hot:
                stats["hot"] += 1
            mark = "★ " if hot else "  "
            if d == "req":
                stats["java_req"] += 1
                line = f"{mark}[REQ] {payload.get('method','')} {url}"
                print(line)
                logf.write(f"{ts} {line}\n")
                hdr = payload.get("headers", "")
                body = payload.get("body", "")
                if hdr:
                    logf.write(f"      headers:\n{hdr}\n")
                if body:
                    logf.write(f"      body: {body}\n")
                    if hot:
                        print(f"      body: {body[:300]}")
                logf.flush()
            else:
                stats["java_resp"] += 1
                line = f"{mark}[RESP {payload.get('code','')}] {url}"
                print(line)
                logf.write(f"{ts} {line}\n")
                body = payload.get("body", "")
                if body:
                    logf.write(f"      resp_body: {body}\n")
                logf.flush()
            reqf.write(json.dumps({"ts": ts, "hot": hot, **payload}, ensure_ascii=False) + "\n")
            reqf.flush()
            return

        # native 兜底数据包
        if isinstance(payload, dict) and "t" in payload:
            stats["native"] += 1
            text = _decode(data) if data else ""
            owner = payload.get("ssl", "")
            head = text[:24].upper()
            if head.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HTTP/")) or HILITE.search(text or ""):
                mark = "★ " if HILITE.search(text or "") else "  "
                d = ">>>" if payload["t"] == "w" else "<<<"
                snippet = text[:200].replace("\n", " ").replace("\r", "")
                line = f"{mark}{d}[{owner}] {snippet}"
                print(line)
                logf.write(f"{ts} {line}\n"); logf.flush()

    script = session.create_script(code)
    script.on("message", on_message)
    script.load()

    print("\n[*] v3 抓包已启动。在雷电 GoPay 里操作：")
    print("    账户 → 已连接的应用(Linked apps) → OpenAI LLC → 解绑")
    print("[*] ★ = 命中关键词。先随便点几下确认有 [REQ]/[RESP] 流水，再走解绑。Ctrl+C 停止。\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[*] Java请求={stats['java_req']} Java响应={stats['java_resp']} "
              f"native包={stats['native']} 命中★={stats['hot']}")
        print(f"[*] 日志: {LOG}")
        print(f"[*] 结构化: {REQ_JSONL}")
        try:
            script.unload()
        except Exception:
            pass
        session.detach()
        logf.close(); reqf.close()
        print("[*] Done。把 ld_v3_traffic.log 里带 ★ 的（含 body）贴回来。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
