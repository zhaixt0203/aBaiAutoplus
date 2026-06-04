#!/usr/bin/env python3
"""GoPay 抓包诊断 —— 找出该 hook 哪里的 SSL 函数。

ld_capture.js 按导出符号(findExportByName)找 SSL_read/SSL_write 失败，说明
GoPay 的 TLS 库(很可能 libflutter.so 里静态链接的 BoringSSL)把符号 strip 了。
这个脚本枚举：
  1. 所有已加载模块里跟网络/TLS 相关的 .so（flutter/ssl/cronet/boring/...）
  2. 这些模块的 exports 和 symbols 里名字含 SSL/ssl 的项（含地址）
  3. 用 ApiResolver 搜 *SSL_read* / *SSL_write* / *ssl_read* / *ssl_write*

跑法：
    python ld_diag.py --host 127.0.0.1:19876
把全部输出贴回来即可。
"""
from __future__ import annotations

import argparse
import sys

try:
    import frida
except ImportError:
    print("[!] 没装 frida：pip install frida==17.9.11")
    sys.exit(1)

JS = r"""
'use strict';
function L(m){ send('' + m); }

var KEYS = ['flutter','ssl','cronet','boring','conscrypt','monochrome','webview',
            'crypto','netty','okhttp','tls','quic','net.so','chrome'];

function interesting(name){
    var n = name.toLowerCase();
    for (var i=0;i<KEYS.length;i++){ if (n.indexOf(KEYS[i])!==-1) return true; }
    return false;
}

L('==== 1. 相关模块 ====');
var mods = Process.enumerateModules();
L('总模块数: ' + mods.length);
mods.forEach(function(m){
    if (interesting(m.name)) {
        L('  MOD ' + m.name + '  base=' + m.base + ' size=' + m.size + '  ' + m.path);
    }
});

function scanModule(modName){
    var m = Process.findModuleByName(modName);
    if (!m){ return; }
    L('==== 2. ' + modName + ' 符号扫描 ====');

    // exports
    var exp = [];
    try { exp = m.enumerateExports(); } catch(e){ L('  enumerateExports err: '+e); }
    L('  exports 总数: ' + exp.length);
    var expSSL = exp.filter(function(e){ return /ssl_(read|write)|SSL_(read|write|CTX_set_verify|set_verify|get_verify)/i.test(e.name); });
    L('  exports 含 SSL_read/write/verify: ' + expSSL.length);
    expSSL.slice(0,40).forEach(function(e){ L('    EXP ' + e.name + ' @ ' + e.address); });

    // symbols (可能含 strip 后残留的 local symbol)
    var sym = [];
    try { sym = m.enumerateSymbols(); } catch(e){ L('  enumerateSymbols err: '+e); }
    L('  symbols 总数: ' + sym.length);
    var symSSL = sym.filter(function(s){ return /ssl_(read|write)|SSL_(read|write)/i.test(s.name); });
    L('  symbols 含 ssl read/write: ' + symSSL.length);
    symSSL.slice(0,40).forEach(function(s){ L('    SYM ' + s.name + ' @ ' + s.address + ' type=' + s.type); });
}

['libflutter.so','libssl.so','libcronet.so','libmonochrome.so',
 'libssl_conscrypt_jni.so','libconscrypt_jni.so'].forEach(scanModule);

L('==== 3. ApiResolver 搜 SSL_read/SSL_write ====');
try {
    var r = new ApiResolver('module');
    ['exports:*!*SSL_read*','exports:*!*SSL_write*',
     'exports:*!*ssl_read*','exports:*!*ssl_write*'].forEach(function(q){
        var found = [];
        try { found = r.enumerateMatches(q); } catch(e){}
        L('  query ' + q + ' -> ' + found.length + ' 命中');
        found.slice(0,15).forEach(function(f){ L('    ' + f.name + ' @ ' + f.address); });
    });
} catch(e){ L('  ApiResolver err: '+e); }

L('==== DIAG DONE ====');
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:19876")
    args = ap.parse_args()

    device = frida.get_device_manager().add_remote_device(args.host)
    pid = None
    for p in device.enumerate_processes():
        nl = p.name.lower()
        if ("gopay" in nl or "gojek" in nl) and "notification" not in nl:
            pid = p.pid
            print(f"[*] attach {p.name} (PID={p.pid})")
            break
    if not pid:
        print("[!] 没找到 GoPay 进程，先在雷电里打开 GoPay")
        return 1

    session = device.attach(pid)
    done = {"v": False}

    def on_message(msg, data):
        if msg.get("type") == "send":
            print(msg["payload"])
            if msg["payload"] == "==== DIAG DONE ====":
                done["v"] = True
        elif msg.get("type") == "error":
            print(f"[ERR] {msg.get('description') or msg}")

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()

    import time
    for _ in range(30):
        if done["v"]:
            break
        time.sleep(0.5)
    try:
        script.unload()
    except Exception:
        pass
    session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
