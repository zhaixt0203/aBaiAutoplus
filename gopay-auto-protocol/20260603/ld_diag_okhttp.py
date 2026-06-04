#!/usr/bin/env python3
"""枚举 GoPay 里的 OkHttp / 网络类，找出真实(可能被混淆/重打包的)类名。

v3 的 Java hook 没触发(Java请求=0)，需要先确认 OkHttp 类到底叫什么。
这个脚本：
  1. 列出所有含 okhttp / RealCall / Interceptor / RealInterceptorChain 的已加载类
  2. 对每个疑似 Chain 类，打印它的方法签名（找 proceed(Request) 那种）
跑法：
    python ld_diag_okhttp.py --host 127.0.0.1:19876
GoPay 要先在前台跑一下网络（点开有数据的页面）让 OkHttp 类被加载。
把输出全部贴回来。
"""
from __future__ import annotations
import argparse, sys, time

try:
    import frida
except ImportError:
    print("[!] pip install frida==17.9.11"); sys.exit(1)

JS = r"""
'use strict';
function L(m){ send(''+m); }
if (!Java.available) { L('[!] Java 不可用'); }
else Java.perform(function(){
    var hits = [];
    var seen = {};
    Java.enumerateLoadedClasses({
        onMatch: function(name){
            var n = name.toLowerCase();
            if (n.indexOf('okhttp') !== -1 ||
                /\.realcall$/.test(n) ||
                /interceptorchain$/.test(n) ||
                /\.realinterceptorchain$/.test(n) ||
                n.indexOf('interceptor') !== -1) {
                hits.push(name);
            }
        },
        onComplete: function(){
            L('==== OkHttp/Interceptor 相关类 (' + hits.length + ') ====');
            hits.slice(0, 200).forEach(function(c){ L('  ' + c); });

            // 找疑似 Chain：类名含 Chain 且有 proceed 方法
            L('==== 疑似拦截链类的 proceed 方法 ====');
            hits.forEach(function(c){
                if (!/chain/i.test(c)) return;
                try {
                    var K = Java.use(c);
                    var ms = K.class.getDeclaredMethods();
                    for (var i=0;i<ms.length;i++){
                        var sig = ms[i].toString();
                        if (/proceed|intercept/i.test(sig)) {
                            L('  [' + c + '] ' + sig);
                        }
                    }
                } catch(e){}
            });

            // 找 OkHttpClient.newCall 入口（最稳的统一 hook 点）
            L('==== 含 newCall 的类 ====');
            hits.forEach(function(c){
                if (!/okhttpclient$/i.test(c)) return;
                try {
                    var K = Java.use(c);
                    var ms = K.class.getDeclaredMethods();
                    for (var i=0;i<ms.length;i++){
                        var sig = ms[i].toString();
                        if (/newcall/i.test(sig)) L('  [' + c + '] ' + sig);
                    }
                } catch(e){}
            });
            L('==== DIAG DONE ====');
        }
    });
});
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:19876")
    args = ap.parse_args()
    dev = frida.get_device_manager().add_remote_device(args.host)
    pid = None
    for p in dev.enumerate_processes():
        nl = p.name.lower()
        if ("gopay" in nl or "gojek" in nl) and "notification" not in nl:
            pid = p.pid; print(f"[*] attach {p.name} ({p.pid})"); break
    if not pid:
        print("[!] 没找到 GoPay"); return 1
    s = dev.attach(pid)
    done = {"v": False}
    def on_msg(m, d):
        if m.get("type") == "send":
            print(m["payload"])
            if m["payload"] == "==== DIAG DONE ====": done["v"] = True
        elif m.get("type") == "error":
            print("[ERR]", m.get("description") or m)
    sc = s.create_script(JS); sc.on("message", on_msg); sc.load()
    for _ in range(40):
        if done["v"]: break
        time.sleep(0.5)
    try: sc.unload()
    except Exception: pass
    s.detach()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
