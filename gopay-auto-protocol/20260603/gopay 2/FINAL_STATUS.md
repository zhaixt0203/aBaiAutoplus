# GoPay 逆向分析最终状态

## 已完成的成果 ✅

### 1. 加密参数已完整捕获

| 参数 | Hex值 | 解码 |
|------|-------|------|
| **AES-128密钥** | `5a584967625746796132563049476c75` | `er market in` |
| **IV** | `5756756443776754573971595735484b` | `WVudCwgTW9qYW5HK` |
| **HMAC-SHA256密钥** | `6e6e336745794670706541525261505275794b783852` | `nn3gEyFppeARRaPRuyKx8R` |

### 2. API端点已识别

| 域名 | 用途 |
|------|------|
| `customer.gopayapi.com` | 客户API |
| `gopay-raccoon.gojekapi.com` | 业务API |
| `imgs-sea.alipay.com` | MGS网关 |
| `imdap-sea.alipay.com` | 日志网关 |

### 3. 配置参数已提取

| 参数 | 值 |
|------|-----|
| AppId | `GOPAY_WALLET_IDN` |
| WorkspaceId | `3505900004151575` |
| apiKey_0a6a | SecurityGuard签名密钥 |
| 签名方法 | signV3 |

### 4. 工具和脚本已创建

| 文件 | 用途 |
|------|------|
| `gopay_api_client.py` | Python API客户端 |
| `frida_pin_hook.js` | PIN码捕获脚本 |
| `frida_http_simple.js` | HTTP钩子脚本 |
| `ENCRYPTION_DISCOVERY.md` | 加密发现报告 |
| `REVERSE_LOG.md` | 逆向分析日志 |

---

## 当前问题 ⚠️

### 1. HTTPS流量无法解密
- GoPay使用证书固定 (Certificate Pinning)
- mitmproxy无法拦截HTTPS流量
- 需要绕过证书固定

### 2. 反Frida检测
- 应用检测到Frida后会退出
- 需要使用更隐蔽的方法

### 3. Operation-Type未知
- API返回"Missing operationtype"错误
- 需要从应用中捕获正确的Operation-Type

---

## 解决方案

### 方案1: 绕过证书固定

使用Frida脚本绕过SSL证书固定：

```javascript
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[SSL Bypass] ' + host);
        return untrustedChain;
    };
});
```

### 方案2: 使用 objection

```bash
objection -g com.gojek.gopay explore
android sslpinning disable
```

### 方案3: 使用Frida gadget

将Frida gadget注入到APK中，绕过反调试检测。

---

## Frida反检测绕过 (2026-05-30 新增)

### 已验证方案: frida-server 17.9.19 + gopay_late_attach.js

**核心发现**: 原版frida-server可以直接attach到Google Play版GoPay，关键点：
1. **frida-server改名**为`.fsrv`（避免`access()`检测）
2. **端口改为19876**（避免`/proc/net/tcp`扫描27042端口）
3. **必须先启动GoPay**，再启动frida-server，再注入脚本

#### 启动步骤

```powershell
# 1. 确保GoPay在设备上运行
adb -s 192.168.2.232:5555 shell monkey -p com.gojek.gopay -c android.intent.category.LAUNCHER 1
sleep 15  # 等待GoPay完全启动

# 2. 启动frida-server (改名.fsrv + 端口19876)
adb -s 192.168.2.232:5555 shell su -c '/data/local/tmp/.fsrv -D -l 0.0.0.0:19876 &'

# 3. 端口转发
adb -s 192.168.2.232:5555 forward tcp:19876 tcp:19876

# 4. 注入反检测脚本 (关键!)
frida -H 127.0.0.1:19876 -p <GoPay_PID> -l gopay_tools/frida/gopay_late_attach.js
```

#### 脚本加载验证输出

```
[CLOAK] 57 threads hidden (one-shot)
[SECCOMP] exit_group + kill/tgkill(9,6,15) blocked (TSYNC)
[STEALTH] 7 native hooks
[SSL] 3 native hooks (immediate)
[ANTI-DET] 7/7 hooks (fopen×2+fread+fclose+faccessat+stat+readlinkat)
[*] Late-attach v2.9 loaded — anti-det + seccomp + SSL unpin
```

#### 脚本防护能力

| 防护层 | 机制 | 目标 |
|--------|------|------|
| **CLOAK** | `Cloak.addThread(tid)` | 隐藏所有frida线程 |
| **SECCOMP** | BPF过滤器 | 阻止kill/tgkill/exit_group系统调用 |
| **STEALTH** | 10个native hook | ptrace/connect/rt_sigqueueinfo/abort/pthread_kill/raise/tkill |
| **SSL** | SSL_CTX_set_verify等 | 禁用证书验证 |
| **ANTI-DET** | fopen+fread+access过滤 | /proc/self/maps、/proc/net/tcp、文件存在性检测 |
| **JAVA** | System.exit/killProcess | 阻止Java层退出 |

### SSL流量捕获 (2026-05-30 验证成功)

**捕获脚本**: `gopay_tools/frida/flutter_traffic_capture.js`

**SSL偏移量**:
| 函数 | 偏移量 | 说明 |
|------|--------|------|
| `SSL_read` | `flutter+0x717e64` | 捕获解密后的读取 |
| `ssl3_write` | `flutter+0x713850` | 捕获加密前的写入 |

**捕获结果**: 51个SSL包，包含完整登录流程：
```
POST /goto-auth/login/methods     → 登录方式
POST /cvs/v1/initiate             → 验证码发送
GET  /api/v2/challenges/{id}/pin-page → PIN页面
POST /api/v1/users/pin/tokens/nb  → JWT Token (已获取)
POST /cvs/v1/verify               → 验证成功 (200 OK)
```

**x-e1签名格式 (V2)**:
```
{hmac_sha256_hex}:{nonce_hex_192chars}:N:{timestamp_ms}
```
**注意**: nonce长度是192字符（不是之前认为的160字符）

**x-e2签名 (新发现)**:
```
{base64主签名}:{base64短签名}
```
现有实现**缺少x-e2**的生成逻辑。

### 失败方案记录

#### ZygiskFrida + frida-gadget (失败)

- **模块**: ZygiskFrida v1.9.0 (https://github.com/lico-n/ZygiskFrida)
- **问题**: frida-gadget 17.4.0在remap后触发SEGV_ACCERR
- **原因**: GoPay的RASP在并发调用mprotect()修改内存页权限，与ZygiskFrida的remap冲突
- **表现**: `signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)`
- **注意**: 在YouTube等无RASP的app上完全正常

#### rusda (反检测编译Frida) (部分失败)

- **项目**: https://github.com/taisuii/rusda (Frida 17.6.2魔改)
- **gadget**: arm64发布物实际是32位，无法用于64位app
- **server**: 在MIUI设备上helper进程因`miui.contentcatcher.InterceptorProxy`初始化失败而崩溃
- **价值**: 提供了反检测编译思路（字符串XOR、符号改名、memfd改名等）

#### 默认端口27042 (失败)

- **问题**: frida-server默认端口27042在`/proc/net/tcp`中暴露为`69A2`
- **表现**: GoPay启动后几秒退出，无明显错误日志
- **解决**: 改用端口19876（`4DA8`）

#### 默认文件名frida-server (失败)

- **问题**: GoPay RASP检查`/data/local/tmp/frida-server`文件是否存在
- **表现**: `ACCESS: /data/local/tmp/frida-server exists=true`
- **解决**: 改名为`.fsrv`

### MIUI兼容性问题

- **问题**: `/data/system/theme_config/theme_compatibility.xml`缺失导致frida helper崩溃
- **修复**: 创建该文件
  ```bash
  adb shell su -c 'mkdir -p /data/system/theme_config && echo "<?xml version=\"1.0\" encoding=\"utf-8\"?><compatibility version=\"140\" size=\"0\" />" > /data/system/theme_config/theme_compatibility.xml'
  ```

### ZygiskFrida导致的Profile损坏

- **问题**: 安装/卸载ZygiskFrida模块后，GoPay因profile编译失败(code 13)而崩溃
- **修复**: 完全卸载GoPay → 清理profile目录 → 重新安装
  ```bash
  adb shell su -c 'pm uninstall com.gojek.gopay; rm -rf /data/misc/profiles/cur/0/com.gojek.gopay /data/misc/profiles/ref/com.gojek.gopay /data_mirror/cur_profiles/0/com.gojek.gopay'
  ```

---

## 下一步行动

1. **捕获HMAC签名** - 在frida注入状态下，hook libbatteryOpt.so捕获真实的V2 HMAC key和消息格式
2. **修复GoPay-1000** - 用捕获的真实签名替换mitmproxy addon中的计算值
3. **完成登录流程** - OTP验证 → PIN设置

---

## 技术总结

GoPay使用了多层安全机制：
1. **AES-128-CBC加密** - 保护请求数据
2. **HMAC-SHA256签名 (V1/V2)** - 防止篡改
3. **TLS证书固定** - Flutter BoringSSL
4. **libaf-android.so RASP** - 运行时反调试（检测frida maps/ptrace/端口）
5. **libbatteryOpt.so** - HMAC密钥生成和签名

反检测策略：
- **gopay_late_attach.js** 是关键 — 通过seccomp BPF + fread过滤 + 线程cloaking，在RASP检测前就位
- **必须先attach再注入** — 脚本需要在RASP开始检测前加载
- **Zygisk方案暂不可行** — frida-gadget的remap与GoPay RASP存在竞态条件

---

*最后更新: 2026-05-30 11:25*
*分析工具: Frida 17.9.11, frida-server 17.9.11, mitmproxy, Python*
*目标设备: 192.168.2.232 (Xiaomi Mi 9T Pro, Android 11, Magisk/Kitsune Mask)*
*GoPay版本: Google Play最新版 (com.gojek.gopay)*
