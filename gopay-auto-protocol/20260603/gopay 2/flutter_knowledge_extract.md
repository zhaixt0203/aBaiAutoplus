# Flutter 逆向知识提取

来源：本地克隆的 `matriy330.github.io` 静态站点。

扫描范围：只统计 `pageType: 'post'` 的文章正文，不把首页、归档页、分类页的摘要算作正文。

## 命中文章

| 路径 | 标题 | 时间 | 说明 |
| --- | --- | --- | --- |
| `6fdbf1b1/index.html` | Android-Flutter逆向原理及实战 | 2026-03-22 | 主体文章，覆盖架构、AOT、blutter、抓包、实战 |
| `ac0392ad/index.html` | Android逆向16-Flutter | 2025-05-08 | Flutter 识别、抓包、reFlutter、反编译概览 |
| `32bbb378/index.html` | WMCTF2025 Want2BecomeMagicalGirl复现 | 2026-03-11 | Java/Dart/native 三层、MethodChannel、FFI、ART hook |
| `6d2ed8b8/index.html` | WMCTF2023 VNCTF2023 BabyAnti 分析 | 2026-03-11 | ObjectPool、Dart String、blutter hook、反调试 |
| `bd334558/index.html` | WMCTF 2025 re wp | 2025-11-03 | Flutter 调用约定、Dart 整数编码、native 调用 |
| `8b3b5504/index.html` | DASCTF 2025下半年赛 RE wp | 2025-12-07 | blutter 导入 IDA、TextEditingController、常量还原 |
| `2ade85f8/index.html` | DASCTF 2023 10 wp | 2025-10-03 | Java 层 VM 与 Frida hook 方法名问题 |
| `f3acfce3/index.html` | Android逆向15-抓包 | 2025-05-07 | 抓包工具和 ProxyPin |
| `c2ef4741/index.html` | Android逆向17-抓包进阶 | 2025-05-09 | r0capture 局限和 eBPF 抓包背景 |

## 1. Flutter App 的逆向特征

Flutter Android APK 通常可以通过这些文件识别：

- `lib/<abi>/libflutter.so`：Flutter Engine，包含 Dart VM、Skia、运行时、TLS 等底层组件。
- `lib/<abi>/libapp.so`：业务 Dart 代码的 AOT 编译产物，release 包里逆向重点通常在这里。
- `assets/flutter_assets/`：Flutter 资源目录，包含资源 manifest、字体、图片等。
- debug 包可能出现 `kernel_blob.bin`、`vm_snapshot_data`、`isolate_snapshot_data` 等快照文件。

和传统 Android 的差别：

- Java/Kotlin 层经常只是容器、生命周期、插件注册、MethodChannel 桥接。
- UI 不是 XML 控件，而是 Dart Widget Tree，经 Flutter Engine/Skia 自绘。
- `uiautomator` 和 Android Layout Inspector 对 Flutter UI 的识别能力有限。
- release 下 Dart 源码、函数名、类型信息通常不可直接获得，核心业务落在 `libapp.so` 的 AOT 代码里。

## 2. Flutter 架构三层

Flutter 逆向时可以按三层拆：

- Framework/Dart 层：Widget、状态管理、业务逻辑、网络请求、Dart 包。
- Engine/C++ 层：Dart VM、Skia、文本布局、GPU 渲染、Platform Channel、部分 TLS 行为。
- Embedder/平台层：Android 上主要是 `FlutterActivity`、`FlutterView`、`FlutterJNI` 和 Java/Kotlin 插件入口。

实战判断：

- 页面和大部分业务逻辑优先从 Dart AOT 里找。
- 生命周期、权限、插件、native 桥接从 Java/Kotlin 和 `AndroidManifest.xml` 找。
- 加密、反调试、证书校验可能分布在 Dart AOT、Java、native so、Engine patch 多个位置。

## 3. AOT 与 Snapshot

release Flutter 的关键链路：

```text
Dart source -> Kernel -> AOT -> native code -> libapp.so
```

`readelf -s libapp.so` 常见符号含义：

- `_kDartVmSnapshotData`：VM isolate 共享的 Dart heap 初始状态。
- `_kDartVmSnapshotInstructions`：VM 共享通用例程和 stub。
- `_kDartIsolateSnapshotData`：main isolate 的 Dart 对象图、常量、类型等初始状态。
- `_kDartIsolateSnapshotInstructions`：main isolate 执行的 AOT 代码，业务相关性最高。

逆向影响：

- AOT 后动态分发信息减少，很多调用变成固定地址调用。
- 字符串和对象通常不是裸地址直接引用，而是经 ObjectPool / snapshot 对象图间接访问。
- 不能只靠 IDA 对 `.rodata` 字符串的普通 xref 判断逻辑路径。

## 4. ObjectPool 与 Dart 对象

Flutter release 的 Dart 字符串、List、Map、Type、Class、Field 等常量，经常通过 PP/ObjectPool 取：

```text
AOT code -> PP/ObjectPool slot -> Dart object -> payload
```

典型 ARM64 形态：

```asm
LDR X0, [X27, #offset]
```

其中 `X27` 常作为 Pool Pointer。`pp.txt` 可以理解为 ObjectPool 视角，`obj.txt` 可以理解为反序列化后的 Dart heap object graph 视角。

分析经验：

- 看到明文字符串但没有 xref，不代表没用到；可能代码引用的是 Dart String 对象头或 ObjectPool slot。
- blutter 生成的 `asm/*.dart` 比 IDA 裸反汇编更适合追 Dart 层调用。
- UI 逻辑常藏在 closure、`setState()`、`TextEditingController.text`、`LoadField`/`StoreField` 读写里。

## 5. blutter 基本工作流

常规流程：

```bash
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

然后：

- 把 blutter 输出的 IDA 脚本导入 IDA，用来恢复部分名称和结构。
- 看 `asm/` 目录下的 Dart 文件，优先查 `main.dart`、页面 widget、路由、`check`、`login`、`encrypt`、`decrypt` 等关键词。
- 看 `pp.txt`、`obj.txt` 辅助定位 Dart 常量、字符串、对象。
- 用生成的 `blutter_frida.js` hook Dart AOT 对象，尤其是 Dart String、List、Widget、业务函数。

普通手写 Frida hook 和 blutter hook 的区别：

- 手写 hook 更适合普通 native 函数、C 参数、Java 方法。
- blutter hook 更适合解析 Dart AOT 对象，例如 Dart String、List、Widget、closure 捕获对象。

注意：

- ABI 要匹配；文章里提到 blutter 对 x86_64 场景可能不如 arm64 顺手。
- 如果 APK 只有 x86 模拟器包，可能需要换 arm64 真机/模拟器样本再分析。
- 版本变动会导致地址、包名、函数布局变化，脚本要按版本重算。

## 6. Flutter Dart 层追逻辑套路

常见定位顺序：

1. 从 `main()`、`runApp()`、`MaterialApp`、routes、页面 widget 入口开始。
2. 找 `TextEditingController`、按钮回调、`GestureDetector`、`onPressed`、`setState()`。
3. 看 closure 捕获：`AllocateContext`、`StoreField`、`AllocateClosure`、`LoadField`。
4. 追最终业务调用：`checkFlag`、`login`、`encrypt`、`decrypt`、`parseUser` 等。
5. 对常量数组做 Dart Smi/整数编码还原。

文章中的实战观察：

- Dart 小整数在 AOT 对象里可能以 tagged integer 形式存在，实战里常见现象是数值需要右移一位再使用。
- 某些 Flutter 函数调用参数顺序和 `this` 位置需要结合反汇编验证，不能套 Java/native 习惯。
- 从 UI 输入到算法，常见链路是 `TextEditingController.text -> 加密/变换函数 -> ListEquality.equals/字符串比较`。

## 7. MethodChannel 与 FFI

Flutter App 常见三层协作：

```text
Android Java/Kotlin: 容器、生命周期、插件注册、MethodChannel
Dart: 页面、状态、业务逻辑、调用桥
Native so: FFI、加密、反调试、符号解析、runtime patch
```

MethodChannel 分析点：

- Java/Kotlin 里找 `MethodChannel` 名称、handler、`method` 和 `arguments` 的使用差异。
- 有些题会把真正 payload 放在 `MethodCall.method` 字符串里，而不是 `arguments`。
- Java 层可能对 Dart 传入内容做 XXTEA/AES/RC4 等处理，再 Base64 返回。

FFI 分析点：

- Dart 文件里找 `DynamicLibrary.open`、`lookupFunction`、`native_add.dart` 等桥接代码。
- native so 可能只在用户输入、按钮回调、校验函数触发时加载。
- `getKey()`、`getSym()` 这类函数名经常用于返回密钥、符号地址或系统库解析结果。

## 8. Flutter 抓包知识

Flutter 抓包和普通 Android App 的主要差别在 TLS 栈：

- 普通 Java/Kotlin 网络库：常见是 OkHttp、HttpURLConnection、Retrofit、Volley，底层多走 Android 系统 TLS。
- Flutter Dart `HttpClient`：可能走 Flutter/Dart 自己的 BoringSSL 和证书校验路径。
- WebView、第三方 SDK、插件网络请求仍可能走 Android 系统 TLS，所以同一个 App 里会出现“部分接口能抓，部分 handshake 失败”。

判断：

- 只装系统 CA 就能解密，说明目标接口没有严格 pinning 或请求走了系统 TLS。
- 只有关键接口失败，可能是只对登录、支付、用户接口做了 pinning。
- Flutter Dart 网络失败但 WebView/SDK 请求成功，是混合网络栈的典型现象。

常用方案：

- Reqable/ProxyPin 先确认基础代理链路。
- Frida hook Flutter TLS 相关点，例如 `ssl_verify_peer_cert`、`SSL_CTX_set_custom_verify`、`X509_verify_cert`。
- Dart 层关注 `badCertificateCallback`。
- patch `libflutter.so` 让证书校验返回成功。
- reFlutter、frida-flutter、objection 作为辅助工具。

r0capture 局限：

- 对 Java 层常见网络库覆盖好。
- 对 Flutter、自研 SSL、WebView/小程序/融合框架不一定通杀。
- 遇到 Flutter Dart TLS 时，要准备走 Engine/native 层证书校验或内核/eBPF方向。

## 9. 反调试与 Frida 对抗

文章里的 Flutter 例题常见反调试点：

- root 检测、设备修改检测、Frida/maps 检测。
- 扫 `/proc/self/maps` 查 `frida` 字符串。
- 使用 `mincore`/`svc` 枚举内存页，绕开单纯文件系统检测。
- runtime 生成 shellcode：`mmap -> memcpy -> mprotect(PROT_EXEC) -> jump`。

处理思路：

- 轻量目标可先用 Frida 替换检测函数返回值。
- 如果检测代码运行得很早，要在 so 加载时就装 hook，或直接 patch so。
- 对动态 shellcode/mincore 扫描，静态 patch、真机环境清理、隐藏 Frida 特征往往比后置 hook 更稳。
- CTF 里可以考虑不跑目标，直接静态还原 Dart AOT 逻辑。

## 10. 实战模式总结

### BabyAnti 类

- 用 blutter 分析 `libapp.so`，导入 IDA 辅助脚本。
- 不要依赖 `.rodata` 明文 xref；从 ObjectPool 和 `asm/*.dart` 追。
- Overlay、Widget、route 名称可以定位隐藏页面或 flag 页面。
- blutter 的 Frida 模板适合 hook Dart 对象，普通 Frida 更适合 native/Java。

### Want2BecomeMagicalGirl 类

- 先拆层：Java 注册 MethodChannel，Dart 负责 UI 和业务，native so 做 FFI/加密/ART patch。
- Java 层可能只是一条桥：Dart 调 MethodChannel，Java 加密或变换后返回。
- Dart 层重点看 edit view、button callback、`check` 函数和 FFI 调用。
- native 层可能取 key/symbol，也可能 hook ART 解释器路径影响 Java 字节码执行。

### DASCTF Flutter checkFlag 类

- 用 blutter 导出后看 `main.dart` 或相关页面文件。
- 从 `_checkFlag` 找输入读取、常量列表、加密函数和比较函数。
- 如果常量看起来全部是偶数或异常偏大，考虑 Dart tagged integer，还原时先右移一位再参与计算。

### 真实 App 响应解密类

- 先抓接口，确认响应是否统一包在 `data` 字段或 envelope。
- 用 blutter/Frida 找通用解密函数和业务 parser 的分界点。
- 优先 hook 解密后的 JSON/Map 入口，比直接 patch UI 模型字段更稳定。
- 如果 VIP/权限逻辑依赖服务端二次接口，只改用户模型可能只能改 UI，不能改真实播放/下载权限。

## 11. 快速检查清单

- APK 是否含 `libflutter.so`、`libapp.so`、`flutter_assets/`？
- 是 debug/kernel snapshot，还是 release/AOT？
- 目标 ABI 是 arm64 还是 x86/x86_64？
- `libapp.so` 的 snapshot 符号是否存在？
- blutter 是否能生成 `asm/`、`pp.txt`、`obj.txt`？
- UI 输入在哪里进入业务逻辑？
- 字符串没有 xref 时，是否应该从 ObjectPool 找？
- 常量数组是否需要 Dart tagged integer 还原？
- 是否存在 MethodChannel/FFI/native so？
- 抓包失败是系统代理问题、证书信任问题，还是 Flutter Dart TLS/pinning？
- Frida hook 是打普通 native/Java，还是需要解析 Dart AOT 对象？
- 是否有 root/maps/mincore/shellcode 反调试？

## 12. 对 gopay/Flutter 目标的应用优先级

如果后续要分析一个具体 Flutter APK，建议按这个顺序：

1. `apktool`/解包确认 Flutter 指纹和 ABI。
2. 提取 `libapp.so` + `libflutter.so`，跑 blutter。
3. 先静态找页面入口、输入框、按钮回调、网络/加密函数。
4. 再用 Frida 验证关键函数参数和返回值。
5. 抓包时先区分 Java/OkHttp/WebView 请求和 Dart HttpClient 请求。
6. 对证书失败接口优先定位 pinning/TLS 层，不要只反复装 CA。
7. 碰到权限/VIP/播放类逻辑，优先找服务端返回解密点和接口请求参数，而不是只改 UI 字段。
