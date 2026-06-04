/*
 * GoPay Late-Attach Script v2.9 — detection neutralization (fread-based)
 * v2.6: hooked openat/read — WRONG, RASP uses fopen/fread
 * v2.7: hooked fopen+fgets — WRONG, RASP uses fread not fgets
 * v2.8: hooked fgets+strstr — WRONG, RASP uses fread + custom inline matching
 * v2.9: CONFIRMED by dynamic trace: RASP calls fopen→fread(4092)→custom match
 *       - fopen/fopen64: track FILE* for maps/status
 *       - fread: in-place same-length keyword replacement (no buffer size change)
 *       - faccessat/stat: return -1 for detection paths
 *       - readlinkat: spoofs frida dex in /proc/self/fd
 */

var libc = Process.findModuleByName("libc.so");
function findExport(name) { return libc.findExportByName(name); }
function safeRead(ptr_) { try { return ptr_.readCString(); } catch(e) { return null; } }

var MK = ["frida", "gadget", "magisk", "zygisk", "shamiko", "lsposed", "xposed", "busybox",
           "gmain", "gdbus", "gum-js-loop", "pool-frida", "linjector",
           "re.zyg.fri", "libgadget", "frida-agent", "undetected", ".fsrv"];

function filterLine(line) {
    if (!line) return false;
    var ll = line.toLowerCase();
    for (var i = 0; i < MK.length; i++) { if (ll.indexOf(MK[i]) !== -1) return true; }
    return false;
}

// ============ 1. CLOAK — one-shot, hide Frida threads ============
(function() {
    var myTid = Process.getCurrentThreadId();
    var threads = Process.enumerateThreads();
    var n = 0;
    for (var i = 0; i < threads.length; i++) {
        var tid = threads[i].id;
        if (tid !== myTid) {
            try { Cloak.addThread(tid); n++; } catch(e) {}
        }
    }
    send("[CLOAK] " + n + " threads hidden (one-shot)");
})();

// ============ 2. SECCOMP — block self-kill syscalls at kernel level ============
// RASP chain: libc syscall(exit_group) → inline SVC exit_group → kill(self,9)
// Must block: exit_group(94), kill(129)+SIGKILL/SIGABRT, tgkill(131)+SIGKILL/SIGABRT
// Safe: does NOT block exit(93) (thread exit), nor tgkill with RT signals (ART GC)
(function() {
    try {
        var SYS_seccomp = 277;
        var SECCOMP_SET_MODE_FILTER = 1;
        var SECCOMP_FILTER_FLAG_TSYNC = 1;

        // 16-instruction BPF program:
        //  [0]  LD nr
        //  [1]  JEQ 94  → [15] ERRNO (exit_group)
        //  [2]  JEQ 129 → [5]  check kill signal
        //  [3]  JEQ 131 → [10] check tgkill signal
        //  [4]  RET ALLOW
        //  -- kill signal check (args[1] = offset 24) --
        //  [5]  LD args[1]
        //  [6]  JEQ 9   → [15] ERRNO (SIGKILL)
        //  [7]  JEQ 6   → [15] ERRNO (SIGABRT)
        //  [8]  JEQ 15  → [15] ERRNO (SIGTERM)
        //  [9]  RET ALLOW
        //  -- tgkill signal check (args[2] = offset 32) --
        //  [10] LD args[2]
        //  [11] JEQ 9   → [15] ERRNO (SIGKILL)
        //  [12] JEQ 6   → [15] ERRNO (SIGABRT)
        //  [13] JEQ 15  → [15] ERRNO (SIGTERM)
        //  [14] RET ALLOW
        //  [15] RET ERRNO(EPERM)

        var N = 16;
        var bpf = Memory.alloc(N * 8);
        function W(i, code, jt, jf, k) {
            var o = bpf.add(i * 8);
            o.writeU16(code); o.add(2).writeU8(jt); o.add(3).writeU8(jf); o.add(4).writeU32(k);
        }
        var LD = 0x0020, JEQ = 0x0015, RET = 0x0006;
        var ALLOW = 0x7fff0000, ERRNO_EPERM = 0x00050001;

        W(0,  LD,  0, 0, 0);       // LD nr
        W(1,  JEQ, 13, 0, 94);     // exit_group → [15]
        W(2,  JEQ, 2,  0, 129);    // kill → [5]
        W(3,  JEQ, 6,  0, 131);    // tgkill → [10]
        W(4,  RET, 0, 0, ALLOW);
        W(5,  LD,  0, 0, 24);      // LD args[1] (kill signal)
        W(6,  JEQ, 8, 0, 9);       // SIGKILL → [15]
        W(7,  JEQ, 7, 0, 6);       // SIGABRT → [15]
        W(8,  JEQ, 6, 0, 15);      // SIGTERM → [15]
        W(9,  RET, 0, 0, ALLOW);
        W(10, LD,  0, 0, 32);      // LD args[2] (tgkill signal)
        W(11, JEQ, 3, 0, 9);       // SIGKILL → [15]
        W(12, JEQ, 2, 0, 6);       // SIGABRT → [15]
        W(13, JEQ, 1, 0, 15);      // SIGTERM → [15]
        W(14, RET, 0, 0, ALLOW);
        W(15, RET, 0, 0, ERRNO_EPERM);

        var fprog = Memory.alloc(16);
        fprog.writeU16(N);
        fprog.add(8).writePointer(bpf);

        var prctl = new NativeFunction(findExport("prctl"), "int", ["int", "long", "long", "long", "long"]);
        prctl(38, 1, 0, 0, 0); // PR_SET_NO_NEW_PRIVS

        var syscallFn = new NativeFunction(findExport("syscall"), "long",
            ["int", "int", "int", "pointer"]);
        var ret = syscallFn(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, fprog);
        var retVal = ret.toInt32 ? ret.toInt32() : Number(ret);

        if (retVal === 0) {
            send("[SECCOMP] exit_group + kill/tgkill(9,6,15) blocked (TSYNC)");
        } else {
            send("[SECCOMP] install failed: " + retVal);
        }
    } catch(e) { send("[SECCOMP] error: " + e); }
})();

// ============ 3. MINIMAL NATIVE HOOKS ============
var hooked = 0;

// ptrace → return 0
try {
    var pt = findExport("ptrace");
    if (pt) Interceptor.replace(pt, new NativeCallback(function() { return 0; }, "long", ["int","int","pointer","pointer"]));
    hooked++;
} catch(e) {}

// connect → block Frida ports only
try {
    Interceptor.attach(findExport("connect"), {
        onEnter: function(a) {
            this.bl = false;
            try {
                var sa = a[1];
                if (sa.readU16() === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    if (port === 27042 || port === 27043) this.bl = true;
                }
            } catch(e) {}
        },
        onLeave: function(r) { if (this.bl) r.replace(ptr(-1)); }
    });
    hooked++;
} catch(e) {}

// pthread_setname_np → rename Frida threads
try {
    Interceptor.attach(findExport("pthread_setname_np"), {
        onEnter: function(a) {
            var name = safeRead(a[1]);
            if (name && filterLine(name)) a[1] = Memory.allocUtf8String("pool-worker");
        }
    });
    hooked++;
} catch(e) {}

// syscall() hook — catch exit/exit_group via libc wrapper (belt + suspenders with seccomp)
try {
    Interceptor.attach(findExport("syscall"), {
        onEnter: function(a) {
            var nr = a[0].toInt32();
            if (nr === 93 || nr === 94) {
                send("[BLOCK] syscall(" + (nr === 93 ? "exit" : "exit_group") + ") blocked!");
                // Redirect to getpid (harmless, returns pid)
                a[0] = ptr(172);
            }
        }
    });
    hooked++;
} catch(e) {}

// exit / _exit → block (libc wrappers)
try {
    Interceptor.replace(findExport("exit"), new NativeCallback(function(code) {
        send("[BLOCK] exit(" + code + ") blocked!");
    }, "void", ["int"]));
    hooked++;
} catch(e) {}

try {
    Interceptor.replace(findExport("_exit"), new NativeCallback(function(code) {
        send("[BLOCK] _exit(" + code + ") blocked!");
    }, "void", ["int"]));
    hooked++;
} catch(e) {}

// kill/tgkill — block self-targeted SIGKILL/SIGABRT/SIGTERM
try {
    Interceptor.attach(findExport("kill"), {
        onEnter: function(a) {
            this.bl = false;
            var pid = a[0].toInt32();
            var sig = a[1].toInt32();
            if (pid === Process.id && (sig === 9 || sig === 6 || sig === 15)) {
                send("[BLOCK] kill(self, " + sig + ") blocked!");
                this.bl = true;
            }
        },
        onLeave: function(r) { if (this.bl) r.replace(ptr(0)); }
    });
    hooked++;
} catch(e) {}

// rt_sigqueueinfo — block self-targeted signals (RASP uses this to bypass kill/tgkill)
try {
    var rtSigqueueinfo = findExport("rt_sigqueueinfo");
    if (rtSigqueueinfo) {
        Interceptor.attach(rtSigqueueinfo, {
            onEnter: function(a) {
                this.bl = false;
                var pid = a[0].toInt32();
                // Second arg is siginfo_t*, sig is at offset 4 (si_signo)
                try {
                    var sig = a[1].add(4).readU32();
                    if (pid === Process.id && (sig === 6 || sig === 9 || sig === 15)) {
                        send("[BLOCK] rt_sigqueueinfo(self, " + sig + ") blocked!");
                        this.bl = true;
                    }
                } catch(e) {}
            },
            onLeave: function(r) { if (this.bl) r.replace(ptr(-1)); }
        });
        hooked++;
    }
} catch(e) {}

// raise — block self-targeted signals
try {
    var raiseAddr = findExport("raise");
    if (raiseAddr) {
        Interceptor.attach(raiseAddr, {
            onEnter: function(a) {
                var sig = a[0].toInt32();
                if (sig === 6 || sig === 9 || sig === 15) {
                    send("[BLOCK] raise(" + sig + ") blocked!");
                    a[0] = ptr(0);  // Change to signal 0 (no-op)
                }
            }
        });
        hooked++;
    }
} catch(e) {}

// abort — block (RASP calls abort after failed kill)
try {
    var abortAddr = findExport("abort");
    if (abortAddr) {
        Interceptor.attach(abortAddr, {
            onEnter: function(a) {
                send("[BLOCK] abort() blocked!");
                this.bl = true;
            },
            onLeave: function(r) { if (this.bl) r.replace(ptr(0)); }
        });
        hooked++;
    }
} catch(e) {}

// pthread_kill — block self-targeted SIGABRT/SIGKILL
try {
    var pthreadKill = findExport("pthread_kill");
    if (pthreadKill) {
        Interceptor.attach(pthreadKill, {
            onEnter: function(a) {
                this.bl = false;
                var sig = a[1].toInt32();
                if (sig === 6 || sig === 9 || sig === 15) {
                    send("[BLOCK] pthread_kill(self, " + sig + ") blocked!");
                    this.bl = true;
                }
            },
            onLeave: function(r) { if (this.bl) r.replace(ptr(0)); }
        });
        hooked++;
    }
} catch(e) {}

// tkill/tgkill — block self-targeted signals (additional layer)
try {
    var tkill = findExport("tkill");
    if (tkill) {
        Interceptor.attach(tkill, {
            onEnter: function(a) {
                this.bl = false;
                var tid = a[0].toInt32();
                var sig = a[1].toInt32();
                if (sig === 6 || sig === 9 || sig === 15) {
                    send("[BLOCK] tkill(" + tid + ", " + sig + ") blocked!");
                    this.bl = true;
                }
            },
            onLeave: function(r) { if (this.bl) r.replace(ptr(0)); }
        });
        hooked++;
    }
} catch(e) {}

send("[STEALTH] " + hooked + " native hooks");

// ============ 4. NATIVE SSL UNPIN (immediate) ============
try {
    var libssl = Process.findModuleByName("libssl.so");
    if (libssl) {
        var sslHooked = 0;
        try { Interceptor.attach(libssl.findExportByName("SSL_CTX_set_verify"), { onEnter: function(a) { a[1] = ptr(0); } }); sslHooked++; } catch(e) {}
        try { Interceptor.attach(libssl.findExportByName("SSL_set_verify"), { onEnter: function(a) { a[1] = ptr(0); } }); sslHooked++; } catch(e) {}
        try { Interceptor.attach(libssl.findExportByName("SSL_get_verify_result"), { onLeave: function(r) { r.replace(ptr(0)); } }); sslHooked++; } catch(e) {}
        send("[SSL] " + sslHooked + " native hooks (immediate)");
    }
} catch(e) {}

// ============ 4a. ANTI-DETECTION: neutralize RASP detection at source ============
// Dynamic trace findings (v2.8 trace at T=279s):
//   RASP calls: fopen("/proc/self/maps") at af+0xa7e20
//               fread(buf, 1, 4092, fp) at af+0x850cc  ← bulk read, NOT fgets
//               custom inline string matching            ← NOT libc strstr
//   Opens maps FRESH each cycle (not pre-opened).
//   Zero strstr/strcmp/memmem calls from libaf — all string matching is inlined.
// v2.9: hook fopen (track FILE*) + fread (filter content) + fclose (cleanup)
//       In-place keyword replacement (same length) avoids buffer offset issues.

var mapsFiles = {};  // FILE*.toString() → "maps"|"status"
var adHooked = 0;

// Same-length replacement pairs for in-place buffer patching
var REPLACE_PAIRS = [
    ["rwxp", "r-xp"],
    ["frida", "fxida"],
    ["Frida", "Fxida"],
    ["FRIDA", "FXIDA"],
    ["gadget", "gxdget"],
    ["magisk", "mxgisk"],
    ["zygisk", "zxgisk"],
    ["shamiko", "shxmiko"],
    ["lsposed", "lsxosed"],
    ["xposed", "xxosed"],
    ["busybox", "bxsybox"],
    ["gmain", "gxain"],
    ["gdbus", "gxbus"],
    ["gum-js-loop", "gxm-js-loop"],
    ["pool-frida", "pool-fxida"],
    ["linjector", "lxnjector"],
    ["libgadget", "libgxdget"],
    ["frida-agent", "fxida-agent"],
    ["undetected", "undxtected"],
    ["4DA8", "XXXX"],  // frida port 19876 hex
    ["4DA9", "XXXX"]   // frida control port hex
];

function patchBuffer(buf, len) {
    try {
        var content = buf.readUtf8String(len);
        if (!content) return false;
        var changed = false;
        for (var i = 0; i < REPLACE_PAIRS.length; i++) {
            var find = REPLACE_PAIRS[i][0];
            var repl = REPLACE_PAIRS[i][1];
            var idx = content.indexOf(find);
            while (idx !== -1) {
                content = content.substring(0, idx) + repl + content.substring(idx + find.length);
                changed = true;
                idx = content.indexOf(find, idx + repl.length);
            }
        }
        // Also patch TracerPid
        var tpIdx = content.indexOf("TracerPid:\t");
        if (tpIdx !== -1) {
            var nlIdx = content.indexOf("\n", tpIdx);
            if (nlIdx !== -1) {
                var pidStr = content.substring(tpIdx + 11, nlIdx).trim();
                if (pidStr !== "0") {
                    var replacement = "TracerPid:\t0";
                    var pad = (nlIdx - tpIdx) - replacement.length;
                    for (var p = 0; p < pad; p++) replacement += " ";
                    content = content.substring(0, tpIdx) + replacement + content.substring(nlIdx);
                    changed = true;
                }
            }
        }
        if (changed) {
            buf.writeUtf8String(content);
        }
        return changed;
    } catch(e) { return false; }
}

// TCP port filtering — hide frida-server port (19876=0x4DA8) from /proc/net/tcp
function patchTcpBuffer(buf, len) {
    try {
        var content = buf.readUtf8String(len);
        if (!content) return false;
        // Remove lines containing our frida port hex (4DA8)
        var lines = content.split("\n");
        var newLines = [];
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].indexOf("4DA8") === -1 && lines[i].indexOf("4DA9") === -1) {
                newLines.push(lines[i]);
            }
        }
        var result = newLines.join("\n");
        if (result.length !== content.length) {
            buf.writeUtf8String(result);
            return true;
        }
        return false;
    } catch(e) { return false; }
}

// (A) fopen/fopen64 — track FILE* for /proc/self/maps, /proc/self/status, /proc/net/tcp
["fopen", "fopen64"].forEach(function(fname) {
    try {
        var addr = findExport(fname);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function(a) {
                this.trackAs = null;
                var path = safeRead(a[0]);
                if (!path) return;
                var pid = Process.id;
                if (path === "/proc/self/maps" || path === "/proc/" + pid + "/maps") {
                    this.trackAs = "maps";
                } else if (path === "/proc/self/status" || path === "/proc/" + pid + "/status") {
                    this.trackAs = "status";
                } else if (path === "/proc/net/tcp" || path === "/proc/net/tcp6") {
                    this.trackAs = "tcp";
                }
            },
            onLeave: function(r) {
                if (this.trackAs && !r.isNull()) {
                    mapsFiles[r.toString()] = this.trackAs;
                }
            }
        });
        adHooked++;
    } catch(e) {}
});

// (B) fread — filter detection content from tracked FILE* reads
//     fread(void *buf, size_t size, size_t n, FILE *stream)
//     RASP reads 4092-byte chunks. We do in-place same-length keyword replacement.
try {
    Interceptor.attach(findExport("fread"), {
        onEnter: function(a) {
            this.patch = false;
            this.type = null;
            var fp = a[3].toString();
            if (mapsFiles[fp] !== undefined) {
                this.buf = a[0];
                this.patch = true;
                this.type = mapsFiles[fp];
            }
        },
        onLeave: function(r) {
            if (!this.patch) return;
            var bytesRead = r.toInt32();
            if (bytesRead <= 0) return;
            if (this.type === "tcp") {
                patchTcpBuffer(this.buf, bytesRead);
            } else {
                patchBuffer(this.buf, bytesRead);
            }
        }
    });
    adHooked++;
} catch(e) {}

// (C) fclose — clean up tracked FILE*
try {
    Interceptor.attach(findExport("fclose"), {
        onEnter: function(a) {
            var fp = a[0].toString();
            if (mapsFiles[fp] !== undefined) delete mapsFiles[fp];
        }
    });
    adHooked++;
} catch(e) {}

// (D) faccessat — return -1 (ENOENT) for detection-relevant paths
try {
    Interceptor.attach(findExport("faccessat"), {
        onEnter: function(a) {
            this.block = false;
            var path = safeRead(a[1]);
            if (!path) return;
            if (filterLine(path) || path.indexOf("/sbin/su") !== -1 ||
                path === "/system/xbin/su" || path === "/system/bin/su" ||
                path.indexOf("frida-server") !== -1 || path.indexOf(".fsrv") !== -1 ||
                path.indexOf("/data/local/tmp/frida") !== -1) {
                this.block = true;
            }
        },
        onLeave: function(r) {
            if (this.block) r.replace(ptr(-1));
        }
    });
    adHooked++;
} catch(e) {}

// (D2) access — return -1 for frida-related paths
try {
    Interceptor.attach(findExport("access"), {
        onEnter: function(a) {
            this.block = false;
            var path = safeRead(a[0]);
            if (!path) return;
            if (path.indexOf("frida") !== -1 || path.indexOf(".fsrv") !== -1 ||
                path.indexOf("/data/local/tmp/frida") !== -1) {
                this.block = true;
            }
        },
        onLeave: function(r) {
            if (this.block) r.replace(ptr(-1));
        }
    });
    adHooked++;
} catch(e) {}

// (E) stat — return -1 for magisk/su paths
try {
    Interceptor.attach(findExport("stat"), {
        onEnter: function(a) {
            this.block = false;
            var path = safeRead(a[0]);
            if (!path) return;
            if (filterLine(path) || path.indexOf("/sbin/su") !== -1 ||
                path === "/system/xbin/su" || path === "/system/bin/su") {
                this.block = true;
            }
        },
        onLeave: function(r) {
            if (this.block) r.replace(ptr(-1));
        }
    });
    adHooked++;
} catch(e) {}

// (F) readlinkat — spoof frida paths in /proc/self/fd/* results
try {
    Interceptor.attach(findExport("readlinkat"), {
        onEnter: function(a) {
            this.checkResult = false;
            var path = safeRead(a[1]);
            if (path && path.indexOf("/proc/") === 0 && path.indexOf("/fd/") !== -1) {
                this.buf = a[2];
                this.bufsiz = a[3].toInt32();
                this.checkResult = true;
            }
        },
        onLeave: function(r) {
            if (!this.checkResult) return;
            var len = r.toInt32();
            if (len <= 0) return;
            try {
                var target = this.buf.readUtf8String(len);
                if (target && filterLine(target)) {
                    var fake = "/data/data/com.gojek.gopay/cache/dex_opt.dex (deleted)";
                    if (fake.length < this.bufsiz) {
                        this.buf.writeUtf8String(fake);
                        r.replace(ptr(fake.length));
                    }
                }
            } catch(e) {}
        }
    });
    adHooked++;
} catch(e) {}

send("[ANTI-DET] " + adHooked + "/7 hooks (fopen×2+fread+fclose+faccessat+stat+readlinkat)");

send("[*] Late-attach v2.9 loaded — anti-det + seccomp + SSL unpin");

// ============ 5. JAVA HOOKS — DELAYED 15s ============
setTimeout(function() {
    send("[JAVA] Loading Java bridge...");
    try {
        if (typeof Java !== "undefined" && Java.available) { Java.perform(function() {
                var javaHooks = 0;

                // Java SSL unpin disabled — interferes with LoginSDK TLS
                // Flutter-layer SSL bypass (flutter_ssl_bypass.js) handles BoringSSL

                // Debug.isDebuggerConnected → false
                try {
                    Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
                    javaHooks++;
                } catch(e) {}

                // Block RASP exit — System.exit, Runtime.exit, Process.killProcess
                try {
                    Java.use("java.lang.System").exit.implementation = function(code) {
                        send("[BLOCK] System.exit(" + code + ") blocked!");
                    };
                    javaHooks++;
                } catch(e) {}

                try {
                    Java.use("java.lang.Runtime").exit.implementation = function(code) {
                        send("[BLOCK] Runtime.exit(" + code + ") blocked!");
                    };
                    javaHooks++;
                } catch(e) {}

                try {
                    Java.use("android.os.Process").killProcess.implementation = function(pid) {
                        if (pid === Process.id) {
                            send("[BLOCK] Process.killProcess(" + pid + ") blocked!");
                            return;
                        }
                        this.killProcess(pid);
                    };
                    javaHooks++;
                } catch(e) {}

                send("[JAVA] " + javaHooks + " hooks installed (SSL + stealth + exit block)");
            });
        } else {
            send("[!] Java not available");
        }
    } catch(e) { send("[!] Java hooks failed: " + e); }
}, 15000);

// ============ 6. HEARTBEAT ============
var hbN = 0;
setInterval(function() {
    hbN++;
    send("[HB] " + hbN + " pid=" + Process.id);
}, 30000);
/*
 * Flutter BoringSSL Traffic Capture v5 — phone-side raw dump + host relay
 *
 * Hooks:
 *   SSL_read  @ 0x717e64: capture plaintext reads
 *   ssl3_write@ 0x713850: capture plaintext writes (type=0x17 app data only)
 *
 * Writes raw TLS payloads to /data/local/tmp/gopay_capture_<ts>.bin on the
 * phone so the complete payload survives even if host-side reassembly fails.
 *
 * Phone-side binary record format (per TLS record):
 *   "TLSx" (4B magic)
 *   dir    (1B: 'R'=0x52 | 'W'=0x57)
 *   ts_ms  (8B uint64 LE: Date.now())
 *   ssl    (16B hex ASCII: zero-padded pointer)
 *   len    (4B uint32 LE: payload length)
 *   data   (len bytes: raw TLS payload)
 */

(function() {
    var flutter = Process.findModuleByName("libflutter.so");
    if (!flutter) { setTimeout(arguments.callee, 1000); return; }
    send("[CAP] libflutter.so base=" + flutter.base);

    // --- Phone-side raw dump ---
    var captureTs = Date.now();
    var capturePath = "/data/local/tmp/gopay_capture_" + captureTs + ".bin";
    var phoneDump = null;
    var recordCount = 0;

    try {
        phoneDump = new File(capturePath, "wb");
        send({ type: "phone_dump", path: capturePath });
        send("[CAP] phone dump: " + capturePath);
    } catch(e) {
        try {
            capturePath = "/data/data/com.gojek.gopay/cache/gopay_capture_" + captureTs + ".bin";
            phoneDump = new File(capturePath, "wb");
            send({ type: "phone_dump", path: capturePath });
            send("[CAP] phone dump (app cache): " + capturePath);
        } catch(e2) {
            send("[CAP] phone dump FAILED: " + e.message + " (host-only mode)");
        }
    }

    function saveToPhone(direction, sslPtr, rawData, dataLen) {
        if (!phoneDump) return;
        try {
            var hdr = new ArrayBuffer(33);
            var v = new DataView(hdr);
            // Magic "TLSx"
            v.setUint8(0, 0x54); v.setUint8(1, 0x4C);
            v.setUint8(2, 0x53); v.setUint8(3, 0x78);
            // Direction
            v.setUint8(4, direction === "r" ? 0x52 : 0x57);
            // Timestamp ms (uint64 LE as two uint32)
            var ts = Date.now();
            v.setUint32(5, ts >>> 0, true);
            v.setUint32(9, Math.floor(ts / 4294967296) >>> 0, true);
            // SSL pointer as 16-char zero-padded hex
            var sslHex = sslPtr.toString().replace("0x", "").padStart(16, "0").slice(0, 16);
            for (var i = 0; i < 16; i++) {
                v.setUint8(13 + i, sslHex.charCodeAt(i));
            }
            // Data length
            v.setUint32(29, dataLen, true);

            phoneDump.write(hdr);
            phoneDump.write(rawData);
            recordCount++;
            if (recordCount % 10 === 0) {
                phoneDump.flush();
            }
        } catch(e) {}
    }

    // --- Hooks ---
    var seqNum = 0;

    function emitCapture(type, fid, label, size, sslPtr, bufPtr, readLen) {
        try {
            var data = bufPtr.readByteArray(Math.min(readLen, 131072));
            if (data) {
                saveToPhone(type, sslPtr, data, readLen);
                send({ t: type, f: fid, l: label, s: readLen,
                       seq: seqNum++, ssl: sslPtr.toString() }, data);
            }
        } catch(e) {}
    }

    // SSL_read @ flutter+0x717e64
    var readAddr = flutter.base.add(0x717e64);
    var readFirst = true;
    Interceptor.attach(readAddr, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
        },
        onLeave: function(retval) {
            var ret = retval.toInt32();
            if (ret <= 0) return;
            if (readFirst) { readFirst = false; send("[CAP] >> READ active"); }
            emitCapture("r", "717e64", "ssl_read", ret, this.ssl, this.buf, ret);
        }
    });
    send("[CAP] hooked READ: ssl_read flutter+0x717e64");

    // do_ssl3_write @ flutter+0x713850
    var writeAddr = flutter.base.add(0x713850);
    var writeFirst = true;
    Interceptor.attach(writeAddr, {
        onEnter: function(args) {
            this.ssl = args[0];
            var type;
            try { type = args[2].toInt32(); } catch(e) { type = 0; }
            if (type !== 0x17) return;
            var len;
            try { len = args[4].toInt32(); } catch(e) { len = 0; }
            if (len <= 0 || len > 1048576) return;
            this.buf = args[3];
            this.len = len;
            this.isAppData = true;
        },
        onLeave: function(retval) {
            if (!this.isAppData) return;
            var ret = retval.toInt32();
            if (ret <= 0) return;
            if (writeFirst) { writeFirst = false; send("[CAP] >> WRITE active"); }
            emitCapture("w", "713850", "ssl3_write", this.len, this.ssl, this.buf, this.len);
        }
    });
    send("[CAP] hooked WRITE: ssl3_write flutter+0x713850");

    send("[CAP] v5 capture active — phone dump + host relay");
})();


/*
 * GoPay pFO Security Error Bypass — 终极精准版
 *
 * 分析来源: blutter 静态分析 pp.txt 对象池
 * 关键发现: GoPay-1000 错误字符串 (pp+0x29998) 紧邻两个 pFO 类闭包
 *   [pp+0x299d0] AnonymousClosure: static (0xb63fbc), of [pFO]
 *   [pp+0x299d8] AnonymousClosure: static (0xb63d2c), of [pFO]
 *
 * 这两个闭包就是显示/触发 "Kami ga bisa memverifikasi HP..." 弹窗的函数
 * 另外 pFO 类还有以下关联闭包 (从 addNames.py 提取):
 *   0xb64674, 0xb645f0 — 同一逻辑路径的其他分支
 *   0xb64a7c, 0xb649f8 — 错误处理后续链路
 *
 * 策略: Hook 这些闭包，观察参数；然后在 onLeave 强制替换返回值
 */
(function() {
    var app = Process.findModuleByName('libapp.so');
    if (!app) { send('[pFO] libapp.so not found'); return; }
    send('[pFO] libapp.so base: ' + app.base);

    // pFO 类所有关联闭包的偏移量
    var targets = [
        { off: 0xb63fbc, name: 'pFO::closure_b63fbc (ERROR_TRIGGER_A)' },
        { off: 0xb63d2c, name: 'pFO::closure_b63d2c (ERROR_TRIGGER_B)' },
        { off: 0xb64674, name: 'pFO::closure_b64674 (ERROR_BRANCH_A)'  },
        { off: 0xb645f0, name: 'pFO::closure_b645f0 (ERROR_BRANCH_B)'  },
        { off: 0xb64a7c, name: 'pFO::closure_b64a7c (ERROR_HANDLER_A)' },
        { off: 0xb649f8, name: 'pFO::closure_b649f8 (ERROR_HANDLER_B)' },
    ];

    targets.forEach(function(t) {
        var addr = app.base.add(t.off);
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    // 打印调用栈，找谁在调用它
                    var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                        .map(function(a) {
                            var off = a.sub(app.base);
                            return '    0x' + off.toString(16);
                        }).join('\n');

                    send('\n[!!!] 触发: ' + t.name);
                    send('[!!!] 调用栈 (libapp.so 偏移):\n' + bt);

                    // 记录寄存器 x0 (Dart this/receiver)
                    send('[!!!] x0 (receiver) = ' + this.context.x0);
                    send('[!!!] x1 = ' + this.context.x1);
                    send('[!!!] x2 = ' + this.context.x2);

                    // 标记为想拦截返回值
                    this.shouldBypass = true;
                },
                onLeave: function(retval) {
                    if (!this.shouldBypass) return;
                    send('[pFO] 返回值: ' + retval + ' -> 尝试替换为 true (1)');
                    // Dart 中布尔 true 通常是 Smi(1) = 0x3 (tagged pointer)
                    // 先观察原始返回值，下一步再决定是否替换
                    // retval.replace(ptr('0x3')); // 如果是同步布尔则取消注释
                }
            });
            send('[pFO] Hooked: ' + t.name + ' @ ' + addr);
        } catch(e) {
            send('[pFO] Hook 失败: ' + t.name + ' - ' + e);
        }
    });

    send('[pFO] 所有 Hook 安装完毕！请触发 GoPay-1000 错误...');
})();
