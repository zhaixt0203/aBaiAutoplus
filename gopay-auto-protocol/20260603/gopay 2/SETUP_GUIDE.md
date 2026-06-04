# GoPay 抓包环境配置指南

## 从零开始配置

### 1. 前置条件

| 项目 | 要求 |
|------|------|
| Windows | Python 3.12+, ADB, Frida 17.9.11 |
| Android设备 | Root (Magisk/Kitsune Mask), USB调试 |
| GoPay | Google Play最新版 (`com.gojek.gopay`) |
| 网络 | 设备和PC在同一局域网 |

### 2. 安装Python依赖

```bash
pip install frida-tools==14.8.2 frida==17.9.11
```

### 3. 下载frida-server

```bash
# 下载frida-server 17.9.19 arm64
gh release download 17.9.19 -R frida/frida -p "frida-server-17.9.19-android-arm64.xz" -D .

# 解压
xz -d frida-server-17.9.19-android-arm64.xz
```

### 4. 推送到设备（改名避免检测）

```bash
# 关键：改名为 .fsrv 避免GoPay RASP检测
adb push frida-server-17.9.19-android-arm64 /sdcard/.fsrv
adb shell "su -c 'cp /sdcard/.fsrv /data/local/tmp/.fsrv && chmod 755 /data/local/tmp/.fsrv'"
```

### 5. 启动GoPay

```bash
# 确保GoPay安装好
adb shell "pm list packages | grep gojek"

# 启动GoPay（不需要先启动frida-server）
adb shell "monkey -p com.gojek.gopay -c android.intent.category.LAUNCHER 1"

# 等待15秒让GoPay完全启动
sleep 15

# 确认GoPay在运行
adb shell "ps -A | grep gopay"
```

### 6. 启动frida-server（用非标准端口）

```bash
# 关键：用端口19876（不是默认的27042，避免/proc/net/tcp检测）
adb shell "su -c '/data/local/tmp/.fsrv -D -l 0.0.0.0:19876 &'"

# 端口转发
adb forward tcp:19876 tcp:19876

# 验证frida-server运行
frida-ps -H 127.0.0.1:19876 | head -5
```

### 7. 注入防护脚本（关键步骤）

```bash
# 注入反检测脚本（必须在操作前加载）
frida -H 127.0.0.1:19876 -p <GoPay_PID> -l gopay_tools/frida/gopay_late_attach.js
```

验证输出：
```
[CLOAK] XX threads hidden (one-shot)
[SECCOMP] exit_group + kill/tgkill(9,6,15) blocked (TSYNC)
[STEALTH] 10 native hooks
[SSL] 3 native hooks (immediate)
[ANTI-DET] 8/7 hooks
[*] Late-attach v2.9 loaded — anti-det + seccomp + SSL unpin
```

### 8. 注入SSL抓包脚本

```bash
# 注入SSL流量捕获（hooks SSL_read/ssl3_write）
frida -H 127.0.0.1:19876 -p <GoPay_PID> -l gopay_tools/frida/flutter_traffic_capture.js
```

验证输出：
```
[CAP] libflutter.so base=0x77a996c000
[CAP] hooked READ: ssl_read flutter+0x717e64
[CAP] hooked WRITE: ssl3_write flutter+0x713850
[CAP] v5 capture active
[CAP] >> WRITE active
[CAP] >> READ active
```

### 9. 在GoPay上操作

现在可以在GoPay上登录/注册/浏览，所有流量会自动捕获。

### 10. 查看捕获结果

```bash
# 查看流量日志
cat captures/ssl_traffic.log

# 查看protobuf包
cat captures/protobuf_packets.json

# 拉取设备上的二进制dump
adb shell "su -c 'cat /data/data/com.gojek.gopay/cache/gopay_capture_*.bin'" > captures/ssl_dump.bin

# 解析dump
python captures/parse_ssl_dump.py captures/ssl_dump.bin
```

---

## 关键发现

### GoPay RASP检测点

| 检测方式 | 说明 | 绕过方法 |
|----------|------|----------|
| `access("/data/local/tmp/frida-server")` | 文件存在性检查 | 改名为`.fsrv` |
| `/proc/net/tcp` 端口扫描 | 扫描27042端口 | 使用端口19876 |
| `/proc/self/maps` 扫描 | 检测frida关键字 | `gopay_late_attach.js`过滤 |
| `kill(self, SIGKILL)` | RASP自杀 | seccomp BPF阻止 |
| `rt_sigqueueinfo` | 发送SIGABRT | frida hook阻止 |

### Frida注入流程

```
1. 启动GoPay (不带frida)
2. 等待15秒完全初始化
3. 启动frida-server (.fsrv, 端口19876)
4. 注入防护脚本 (gopay_late_attach.js)
5. 注入抓包脚本 (flutter_traffic_capture.js)
6. 操作GoPay → 自动捕获流量
```

**时序关键**：必须先启动GoPay，再启动frida-server，再注入脚本。

### SSL偏移量（Flutter BoringSSL）

| 函数 | 偏移量 | 说明 |
|------|--------|------|
| `SSL_read` | `flutter+0x717e64` | 捕获解密后的读取 |
| `ssl3_write` | `flutter+0x713850` | 捕获加密前的写入 |

### API流程（登录）

```
POST /goto-auth/login/methods     → 获取登录方式
POST /v1/support/customer/initiate → 客户初始化
POST /cvs/v1/initiate             → 发送验证码
GET  /api/v2/challenges/{id}/pin-page → 获取PIN页面
POST /api/v1/users/pin/tokens/nb  → 获取JWT Token
POST /cvs/v1/verify               → 验证验证码
```

### x-e1签名格式（V2）

```
{hmac_sha256_hex}:{nonce_hex_192chars}:N:{timestamp_ms}
```

**注意**: nonce长度是192字符（不是之前认为的160字符）

### x-e2签名（新发现）

```
{base64主签名}:{base64短签名}
```

现有实现**缺少x-e2**的生成逻辑。

---

## 故障排除

### GoPay启动后几秒退出

**原因**: frida-server文件名或端口被检测
**解决**: 
1. 确认frida-server改名为`.fsrv`
2. 确认端口是19876（不是27042）
3. 确认先启动GoPay，再启动frida-server

### frida注入后GoPay崩溃

**原因**: RASP检测到ptrace
**解决**: 
1. 确认防护脚本加载成功（看到`[SECCOMP]`消息）
2. 如果仍然崩溃，尝试在GoPay启动后立即注入（<5秒内）

### SSL抓包无流量

**原因**: libflutter.so未加载或偏移量错误
**解决**: 
1. 确认输出有`[CAP] libflutter.so base=...`
2. 如果偏移量错误，需要重新计算（当前偏移量适用于GoPay 2.8.0）

### frida-ps连接失败

**原因**: frida-server未运行或端口不对
**解决**: 
```bash
# 检查frida-server
adb shell "ps -A | grep fsrv"

# 重启frida-server
adb shell "su -c 'killall -9 .fsrv'"
adb shell "su -c '/data/local/tmp/.fsrv -D -l 0.0.0.0:19876 &'"
adb forward tcp:19876 tcp:19876
```

---

## 文件清单

| 文件 | 用途 |
|------|------|
| `gopay_tools/frida/gopay_late_attach.js` | 反检测防护脚本 |
| `gopay_tools/frida/flutter_traffic_capture.js` | SSL流量捕获 |
| `captures/ssl_capture.py` | Python自动化捕获 |
| `captures/parse_ssl_dump.py` | 二进制dump解析 |
| `captures/ssl_traffic.log` | 流量日志 |
| `captures/protobuf_packets.json` | protobuf包分析 |
| `gopay_tools/python/gopay_signer.py` | HMAC签名算法 |

---

*最后更新: 2026-05-30 13:30*
*验证环境: Xiaomi Mi 9T Pro, Android 11, Magisk/Kitsune Mask*
*GoPay版本: 2.8.0 (Google Play)*
*Frida版本: 17.9.11*
