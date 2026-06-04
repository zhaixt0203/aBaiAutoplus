/*
 * GoPay SSL 抓包 —— 雷电模拟器 / 通用版 v2（frida 17 兼容）
 * ============================================================
 * 诊断（ld_diag.py）确认：
 *   - GoPay 这版**不加载 libflutter.so**，网络走 Java OkHttp + Conscrypt
 *     → 底层系统 /system/lib64/libssl.so（BoringSSL）
 *   - 系统 libssl.so **导出** SSL_read / SSL_write / SSL_CTX_set_verify
 *
 * v1 失败原因：用了 frida 16 的静态调用 Module.findExportByName(模块名,符号)，
 * 在 frida 17 已移除 → 静默 null。v2 改用 ApiResolver + 模块实例方法定位，
 * 直接 hook 系统 libssl.so 的导出符号。架构/版本无关。
 *
 * 做两件事：
 *   1. 解 SSL pinning（SSL_CTX_set_verify / SSL_set_verify / get_verify_result）
 *   2. 抓 SSL_read（收，明文）/ SSL_write（发，明文），relay 给 PC
 *
 * 输出格式跟 ld_capture.py 兼容：send({t:'r'|'w', s:len, seq:n, ssl:ptr}, data)
 */

'use strict';

function log(msg) { send('' + msg); }

// frida 17 兼容的"按符号名取地址"：优先 ApiResolver，回退模块实例方法。
function resolveExport(symbol, preferModules) {
    // 1) 先在首选模块的导出表里精确找（实例方法，frida 17 OK）
    if (preferModules) {
        for (var i = 0; i < preferModules.length; i++) {
            try {
                var m = Process.findModuleByName(preferModules[i]);
                if (m) {
                    var a = m.findExportByName(symbol);
                    if (a) return { addr: a, owner: preferModules[i] };
                }
            } catch (e) {}
        }
    }
    // 2) ApiResolver 全局精确匹配
    try {
        var r = new ApiResolver('module');
        var matches = r.enumerateMatches('exports:*!' + symbol);
        if (matches && matches.length) {
            return { addr: matches[0].address, owner: matches[0].name };
        }
    } catch (e) {}
    // 3) 最后遍历所有模块实例
    try {
        var mods = Process.enumerateModules();
        for (var j = 0; j < mods.length; j++) {
            try {
                var aa = mods[j].findExportByName(symbol);
                if (aa) return { addr: aa, owner: mods[j].name };
            } catch (e) {}
        }
    } catch (e) {}
    return null;
}

// ---- 1. 解 SSL pinning ----------------------------------------------------
(function unpin() {
    var done = 0;
    [['SSL_CTX_set_verify', 1], ['SSL_set_verify', 1]].forEach(function (pair) {
        var sym = pair[0], argIdx = pair[1];
        var f = resolveExport(sym, ['libssl.so']);
        if (f) {
            try {
                Interceptor.attach(f.addr, { onEnter: function (a) { try { a[argIdx] = ptr(0); } catch (e) {} } });
                done++;
            } catch (e) {}
        }
    });
    var gvr = resolveExport('SSL_get_verify_result', ['libssl.so']);
    if (gvr) {
        try {
            Interceptor.attach(gvr.addr, { onLeave: function (r) { try { r.replace(ptr(0)); } catch (e) {} } });
            done++;
        } catch (e) {}
    }
    log('[unpin] hooked ' + done + ' verify funcs');
})();

// ---- 2. 抓明文 ------------------------------------------------------------
var seq = 0;

function emit(dir, sslPtr, bufPtr, n) {
    if (n <= 0) return;
    try {
        var data = bufPtr.readByteArray(Math.min(n, 131072));
        if (data) send({ t: dir, s: n, seq: seq++, ssl: sslPtr.toString() }, data);
    } catch (e) {}
}

function hookSSL() {
    // 系统 libssl.so 优先；flutter/cronet 兜底（这版 GoPay 没有，但保留通用性）
    var prefer = ['libssl.so', 'libflutter.so', 'libcronet.so', 'libmonochrome.so'];
    var rd = resolveExport('SSL_read', prefer);
    var wr = resolveExport('SSL_write', prefer);

    if (!rd && !wr) return false;
    log('[cap] SSL_read owner=' + (rd ? rd.owner : 'none') +
        '  SSL_write owner=' + (wr ? wr.owner : 'none'));

    var readFirst = true, writeFirst = true;

    if (rd) {
        Interceptor.attach(rd.addr, {
            onEnter: function (a) { this.ssl = a[0]; this.buf = a[1]; },
            onLeave: function (r) {
                var n = r.toInt32();
                if (n <= 0) return;
                if (readFirst) { readFirst = false; log('[cap] >> READ active'); }
                emit('r', this.ssl, this.buf, n);   // 返回值 = 实际读到字节数
            }
        });
        log('[cap] hooked SSL_read @ ' + rd.addr);
    }

    if (wr) {
        Interceptor.attach(wr.addr, {
            onEnter: function (a) {
                this.ssl = a[0]; this.buf = a[1];
                try { this.n = a[2].toInt32(); } catch (e) { this.n = 0; }
            },
            onLeave: function (r) {
                if (this.n <= 0) return;
                if (writeFirst) { writeFirst = false; log('[cap] >> WRITE active'); }
                emit('w', this.ssl, this.buf, this.n);  // 入参 num = 要写字节数
            }
        });
        log('[cap] hooked SSL_write @ ' + wr.addr);
    }
    return true;
}

if (!hookSSL()) {
    log('[cap] SSL 符号暂未就绪，等库加载…');
    var tries = 0;
    var timer = setInterval(function () {
        tries++;
        if (hookSSL() || tries > 120) {
            clearInterval(timer);
            if (tries > 120) log('[cap] ✗ 60s 内仍没定位到 SSL_read/SSL_write（贴日志给我）');
        }
    }, 500);
}

log('[cap] capture script loaded (v2)');
