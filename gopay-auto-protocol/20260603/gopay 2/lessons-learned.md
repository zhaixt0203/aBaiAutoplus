# Lessons Learned

## 2026-06-02

- 在用户中断过克隆/抓取流程后，不要直接假设目录仍存在；继续使用该目录作为 `workdir` 前先 `Resolve-Path` 或 `Test-Path` 校验，缺失时重新克隆/恢复。
- Flutter APK 逆向不要把 smali 当主线。先走 `libapp.so`/Dart AOT/ObjectPool/blutter 输出；Java/smali 只在 MethodChannel 或 native plugin bridge 有证据时辅助确认。
- Frida runtime 验证前先确认 client/server 主版本一致；本地 `frida 17.9.11` 不能稳定 attach 设备端 `frida-server 16.7.19`。
- GoPay 启动退出时不要直接归因到 signature；`tombstone_28` 是 WebView `libwebviewchromium.so` SIGBUS，不能作为签名校验证据。
- PowerShell 运行 Maven exec 参数时要把系统属性整体加引号，例如 `"-Dexec.mainClass=com.gopay.GoPaySignerTest"`，否则 `-D...` 可能被解析错。
- baksmali 反编译 APK 内多 dex 时，输入写成 `"device_232_gopay_apks\base.apk/classes2.dex"` 这种 ZIP 内路径；不要使用无效的 `--dex-file` 参数。
- PowerShell 读取/搜索带 `$` 的 smali 文件名要用单引号，例如 `'CheckResult$values.smali'`，否则 `$values` 会被当变量展开导致路径错误。
- GoPay 签名分析要区分 APK signer telemetry 和协议请求签名。当前证据支持 `X-M1` 设备指纹参与 `X-E1` HMAC 后由服务端校验，暂未证明 APK 签名 mismatch 会在本地 hard block/exit。
- PowerShell 下不要把 `gopay-auto-protocol\*.py` 这类反斜杠通配路径直接传给 `rg` 当 path；用目录加 `-g "*.py"`。复杂含引号的搜索优先用 `Select-String -SimpleMatch` 或 `rg -F` 并注意引号转义。
- `capture_new_algorithm.py` 已支持 `--frida-host`；在 ADB forward 场景优先传 `--frida-host 127.0.0.1:19876`。2026-06-02 的 5 秒只读 attach 已抓到 `customer.gopayapi.com/v1/support/customer/activity` 的 `signing_hmac_enter`，确认 `X-M1` 进入 `X-E1` HMAC message。
- GoPay PIN UI 自动化不要只按 `content-desc="Continue"` 找到就点；必须读取 UI dump 的 `enabled` 状态，输入 PIN 后等 Continue/Confirm 可用再提交，否则会停留在同一 Create PIN 页面还误报完成。
- `xml.etree.ElementTree.Element` 叶子节点布尔值可能是 false；查找 UI node 时不要写 `find_node_a(...) or find_node_b(...)`，先显式判断 `is None`，避免已找到的叶子节点被当成未找到。
- GoPay 当前 `captures/ssl_dump.bin` 是 4 字节大端长度前缀帧，不是旧脚本期待的 `TLSx` magic；`protobuf_packets.json` 里的 chunk/gzip/图片残片不要误判成响应 `data` 加密。
- Frida spawn GoPay 抓启动期 Flutter parser 时，目标进程可能先销毁 script；runner 的 `script.unload()` 和 `session.detach()` 要捕获 `frida.InvalidOperationError`，否则已抓到证据也会以退出异常收尾。
- GoPay Flutter AOT 的 `Map.dataOffset` 在当前样本里是 compressed pointer 指向真正的 `List` 存储，不是 inline key/value 数组；blutter 默认 Map reader 会读偏成 `_Smi@...`，要先解 data field pointer 再读 List slots。
- GoPay Create PIN 的确认页标题是 `Confirm PIN`，第二次输入后底部按钮可能叫 `Save`，不是 `Continue` 或 `Confirm`；确认阶段要把 `Save` 纳入可用按钮集合。
- GoPay Security settings 里可能同时出现多个 `Create PIN` 文案；不要用第一个 partial match 的中心点直接点击。应优先选择 `clickable=true` 且描述包含 `To ensure only you can make transactions` 或 `Change or reset your PIN` 的行，并验证已进入 PIN 设置页后再继续。
- GoPay PIN 的 OTP 阶段不要点第一个 `EditText`；读 WhatsApp OTP 后要先把 GoPay 拉回前台并重新 dump OTP 页面，优先用底部数字键盘输入验证码。最终截图/完成判定必须确认前台包是 `com.gojek.gopay`，否则会把 WhatsApp 列表误判为成功。
