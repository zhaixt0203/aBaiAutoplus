/*
 * GoPay 抓包 v3 —— Java 层 OkHttp + 全栈 native SSL 兜底
 * ============================================================
 * 背景：v2 hook 系统 /system/lib64/libssl.so 只抓到 AppsFlyer 统计，GoPay
 * 核心业务（gopayapi/gojekapi）一条没有 —— 说明业务走自带 BoringSSL/OkHttp，
 * 不经过系统 libssl。
 *
 * 这版双管齐下：
 *   A. Java 层：hook OkHttp 的 Interceptor 链（拿到的是**明文** Request/
 *      Response，含 URL/method/header/body），最稳，绕开 native 库归属问题。
 *      自动适配 okhttp3 重打包后的混淆类名（按方法特征找）。
 *   B. native 兜底：hook **所有**含 SSL_write/SSL_read 导出的模块（不只系统
 *      libssl），按模块分别统计，把业务流量揪出来。
 *
 * 输出跟 ld_capture.py 兼容：
 *   send({t:'r'|'w', s:len, seq:n, ssl:'okhttp'|<ptr>}, <data>)
 * Java 层请求额外发结构化：send({java:1, dir:'req'|'resp', ...})
 */

'use strict';

function log(m) { send('' + m); }
var seq = 0;

// ============ A. Java 层 OkHttp ============
function hookJava() {
    if (!Java.available) { log('[java] Java 不可用'); return; }
    Java.perform(function () {
        var hookedOk = false;

        // --- A1. 直接 hook okhttp3.Interceptor.Chain（标准/重打包都试）---
        var candidates = [
            'okhttp3.internal.http.RealInterceptorChain',
            'com.gojek.okhttp3.internal.http.RealInterceptorChain',
        ];
        candidates.forEach(function (cn) {
            try {
                var C = Java.use(cn);
                // proceed(Request) 是拦截链核心
                C.proceed.overload('okhttp3.Request').implementation = function (req) {
                    try { dumpOkRequest(req); } catch (e) {}
                    var resp = this.proceed(req);
                    try { dumpOkResponse(resp); } catch (e) {}
                    return resp;
                };
                hookedOk = true;
                log('[java] hooked ' + cn + '.proceed');
            } catch (e) {}
        });

        // --- A2. 通用兜底：扫所有已加载类，找 okhttp3.OkHttpClient ---
        if (!hookedOk) {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function (name) {
                        if (/okhttp3?\.OkHttpClient$/.test(name) || /\.RealCall$/.test(name)) {
                            log('[java] 发现 OkHttp 类: ' + name);
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
            log('[java] ⚠ 没 hook 到标准 RealInterceptorChain，可能被混淆。把上面"发现 OkHttp 类"的行贴回来。');
        }

        // --- A3. 再 hook 一层 HttpURLConnection（有些请求不走 okhttp）---
        // 省略：GoPay 基本全 okhttp，先看 A1 效果
    });
}

function dumpOkRequest(req) {
    try {
        var url = req.url().toString();
        var method = req.method();
        // header
        var headers = req.headers().toString();
        // body
        var bodyStr = '';
        var body = req.body();
        if (body) {
            try {
                var Buffer = Java.use('okio.Buffer');
                var buf = Buffer.$new();
                body.writeTo(buf);
                bodyStr = buf.readUtf8();
            } catch (e) {}
        }
        send({ java: 1, dir: 'req', method: method, url: url, headers: headers, body: bodyStr.substring(0, 8000) });
    } catch (e) { log('[java] dumpReq err: ' + e); }
}

function dumpOkResponse(resp) {
    try {
        var req = resp.request();
        var url = req.url().toString();
        var code = resp.code();
        var bodyStr = '';
        try {
            var peek = resp.peekBody(131072);  // 不消费原 body
            bodyStr = peek.string();
        } catch (e) {}
        send({ java: 1, dir: 'resp', code: code, url: url, body: bodyStr.substring(0, 8000) });
    } catch (e) { log('[java] dumpResp err: ' + e); }
}

// ============ B. native 全栈兜底 ============
function hookAllNativeSSL() {
    var r;
    try { r = new ApiResolver('module'); } catch (e) { return; }

    function attachAll(symQuery, dir) {
        var matches = [];
        try { matches = r.enumerateMatches('exports:*!' + symQuery); } catch (e) {}
        matches.forEach(function (mt) {
            var owner = mt.name.split('!')[0].split('/').pop();
            // 系统 libssl 已知只有 appsflyer，仍 hook 但标记 owner，方便区分
            try {
                if (dir === 'w') {
                    Interceptor.attach(mt.address, {
                        onEnter: function (a) {
                            this.ssl = a[0]; this.buf = a[1];
                            try { this.n = a[2].toInt32(); } catch (e) { this.n = 0; }
                        },
                        onLeave: function () {
                            if (this.n <= 0) return;
                            try {
                                var d = this.buf.readByteArray(Math.min(this.n, 131072));
                                if (d) send({ t: 'w', s: this.n, seq: seq++, ssl: owner }, d);
                            } catch (e) {}
                        }
                    });
                } else {
                    Interceptor.attach(mt.address, {
                        onEnter: function (a) { this.ssl = a[0]; this.buf = a[1]; },
                        onLeave: function (ret) {
                            var n = ret.toInt32();
                            if (n <= 0) return;
                            try {
                                var d = this.buf.readByteArray(Math.min(n, 131072));
                                if (d) send({ t: 'r', s: n, seq: seq++, ssl: owner }, d);
                            } catch (e) {}
                        }
                    });
                }
                log('[native] hooked ' + symQuery + ' @ ' + owner);
            } catch (e) {}
        });
    }

    attachAll('SSL_write', 'w');
    attachAll('SSL_read', 'r');
}

// ============ 启动 ============
hookAllNativeSSL();
try { hookJava(); } catch (e) { log('[java] hookJava err: ' + e); }
log('[cap] v3 (okhttp+native) loaded');
