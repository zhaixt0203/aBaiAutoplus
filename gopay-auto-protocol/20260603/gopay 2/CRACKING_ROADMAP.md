# GoPay 完整破解路线图

## 当前进度 vs 目标

```
已完成 ████████████████████░░░░░░░░░░░░░░░░░░░░ 50%
目标   ████████████████████████████████████████████ 100%
```

---

## 已完成 ✅

| 项目 | 状态 | 说明 |
|------|------|------|
| API端点识别 | ✅ 完成 | 40+个端点已发现 |
| 配置解码 | ✅ 完成 | apiKey_0a6a, AppId, WorkspaceId |
| 网络流量捕获 | ✅ 完成 | Firebase, AppsFlyer流量 |
| 签名哈希捕获 | ✅ 部分 | SHA-256哈希已记录 |
| 登录流程理解 | ✅ 完成 | 预登录→OTP→Token |
| UI自动化 | ✅ 完成 | ADB自动化操作设备 |
| **Frida反检测绕过** | ✅ 完成 | frida-server 17.9.11 + gopay_late_attach.js v2.9 |
| **GoPay RASP中和** | ✅ 完成 | seccomp + fread过滤 + 线程cloaking |

---

## 未完成 ❌ - 关键缺失

### 1. signV3 完整算法 ❌ (最关键)

**现状**: 只捕获了SHA-256哈希，未还原完整签名逻辑

**需要**:
```
libaf-android.so (ARM64)
    ↓
Ghidra/IDA逆向
    ↓
还原signV3函数
    ↓
Python实现
```

**难度**: ⭐⭐⭐⭐⭐ (高)

**方法**:
1. 使用Ghidra加载 `libaf-android.so`
2. 搜索 `signV3`, `SecurityGuard`, `sign` 等字符串
3. 定位签名函数入口
4. 分析ARM64汇编逻辑
5. 重写为Python

---

### 2. requestData 加密 ❌ (关键)

**现状**: 不知道请求体如何加密

**需要**:
```
原始数据 → 加密算法 → requestData字段
```

**可能的加密方式**:
- AES-128/256-CBC
- RSA加密
- 混合加密

**方法**:
1. Hook `javax.crypto.Cipher`
2. 捕获加密前后的数据
3. 分析密钥来源

---

### 3. 核心钱包API ❌ (关键)

**现状**: 未捕获余额查询、转账等核心API

**需要发现的Operation-Type**:
```
com.alipay.plus.wallet.getBalance      # 余额查询
com.alipay.plus.wallet.transfer        # 转账
com.alipay.plus.wallet.history         # 交易历史
com.alipay.plus.wallet.qrcode          # 二维码支付
```

**方法**:
1. 登录后触发余额刷新
2. 捕获Operation-Type头
3. 记录完整的请求/响应

---

### 4. Token刷新机制 ❌ (重要)

**现状**: 不知道token如何刷新

**需要**:
```
Token过期 → 刷新请求 → 新Token
```

**方法**:
1. 长时间运行监控
2. 捕获token过期时的请求
3. 分析刷新逻辑

---

### 5. 可用的Python客户端 ❌ (目标)

**现状**: 只有模拟代码，无法实际签名

**需要**:
```python
class GoPayClient:
    def sign_request(self, data):  # 实现signV3
        pass
    
    def get_balance(self):         # 调用余额API
        pass
    
    def transfer(self, to, amount): # 调用转账API
        pass
```

---

## 完整破解所需步骤

### 阶段1: 签名算法还原 (2-3天)

```
步骤1.1: 静态分析
├── 工具: Ghidra / IDA Pro
├── 目标: libaf-android.so
└── 输出: signV3函数伪代码

步骤1.2: 动态验证
├── 工具: Frida
├── 目标: SecurityGuard.sign()
└── 输出: 输入输出数据

步骤1.3: 算法重写
├── 工具: Python
├── 目标: 实现signV3
└── 输出: 可用的签名函数
```

### 阶段2: 加密方式破解 (1-2天)

```
步骤2.1: Hook加密函数
├── 工具: Frida
├── 目标: javax.crypto.Cipher
└── 输出: 加密算法和密钥

步骤2.2: 分析密钥来源
├── 工具: Frida + Ghidra
├── 目标: 密钥生成逻辑
└── 输出: 密钥派生算法

步骤2.3: 实现解密
├── 工具: Python
├── 目标: requestData解密
└── 输出: 可用的解密函数
```

### 阶段3: 核心API捕获 (1天)

```
步骤3.1: 登录并获取Token
├── 工具: Frida + ADB
├── 目标: 完整登录流程
└── 输出: 有效Token

步骤3.2: 触发钱包操作
├── 工具: ADB自动化
├── 目标: 余额查询、转账
└── 输出: 核心Operation-Type

步骤3.3: 记录请求/响应
├── 工具: Frida
├── 目标: 完整的RPC调用
└── 输出: API文档
```

### 阶段4: 客户端构建 (2-3天)

```
步骤4.1: 实现基础框架
├── 工具: Python
├── 目标: HTTP客户端
└── 输出: 基础请求函数

步骤4.2: 集成签名算法
├── 工具: Python
├── 目标: signV3集成
└── 输出: 可签名的客户端

步骤4.3: 实现业务API
├── 工具: Python
├── 目标: 余额、转账、支付
└── 输出: 完整API客户端

步骤4.4: 测试验证
├── 工具: pytest
├── 目标: 验证所有API
└── 输出: 测试报告
```

---

## 技术难点分析

### 难点1: SecurityGuard Lite

```
问题: 白盒加密，密钥分散存储
解决: 
1. 逆向libaf-android.so中的密钥还原函数
2. 使用Frida hook运行时密钥
3. 或绕过SecurityGuard，直接hook签名结果
```

### 难点2: ARM64汇编

```
问题: 需要逆向复杂的ARM64代码
解决:
1. 使用Ghidra的反编译器
2. 重点关注signV3相关函数
3. 对比多个签名样本推断逻辑
```

### 难点3: 动态密钥

```
问题: 签名密钥可能每次请求变化
解决:
1. 捕获多次签名的输入输出
2. 分析密钥是否变化
3. 如变化，逆向密钥派生逻辑
```

### 难点4: 防逆向保护

```
问题: 可能有反调试、完整性校验
解决:
1. 使用Frida绕过反调试
2. Patch掉完整性校验
3. 使用Magisk隐藏root
```

---

## 所需工具清单

### 必需工具

| 工具 | 用途 | 获取方式 |
|------|------|----------|
| Ghidra | ARM64逆向 | 免费下载 |
| Frida | 动态hook | pip install frida |
| Python | 算法实现 | 已安装 |
| ADB | 设备控制 | Android SDK |

### 可选工具

| 工具 | 用途 | 说明 |
|------|------|------|
| IDA Pro | 更强的逆向 | 商业软件 |
| Objection | Frida增强 | pip install objection |
| mitmproxy | 流量拦截 | 已安装 |

---

## 预期时间表

```
第1天: 安装Ghidra，开始逆向libaf-android.so
第2天: 完成signV3函数识别
第3天: 重写signV3为Python
第4天: Hook加密函数，分析requestData
第5天: 登录并捕获核心API
第6天: 构建Python客户端框架
第7天: 集成签名算法，测试
第8天: 实现余额查询API
第9天: 实现转账API
第10天: 测试验证，编写文档
```

---

## 成功标准

### 最小可行产品 (MVP)

- [ ] signV3算法可正确签名
- [ ] 能成功调用预登录API
- [ ] 能完成OTP验证
- [ ] 能获取有效Token

### 完整破解

- [ ] 所有API端点可用
- [ ] 签名算法100%正确
- [ ] Python客户端功能完整
- [ ] 能执行余额查询
- [ ] 能执行转账操作
- [ ] 自动化测试通过

---

## 立即行动项

### 今天可以做的

1. **下载Ghidra**
   ```
   https://ghidra-sre.org/
   ```

2. **导出libaf-android.so**
   ```bash
   adb pull /data/app/com.gojek.gopay/lib/arm64/libaf-android.so
   ```

3. **运行Frida持续监控**
   ```bash
   frida -H 192.168.2.232:27042 -p <PID> -l frida_sign_hook.js
   ```

4. **登录并触发余额查询**
   - 完成登录流程
   - 点击刷新余额
   - 捕获所有RPC调用

---

## 总结

**距离完全破解还差**:

| 项目 | 难度 | 时间 | 优先级 |
|------|------|------|--------|
| signV3算法还原 | ⭐⭐⭐⭐⭐ | 2-3天 | P0 |
| requestData解密 | ⭐⭐⭐⭐ | 1-2天 | P0 |
| 核心API捕获 | ⭐⭐⭐ | 1天 | P1 |
| Token刷新机制 | ⭐⭐⭐ | 1天 | P1 |
| Python客户端 | ⭐⭐⭐⭐ | 2-3天 | P2 |

**总计**: 约 7-10 天可完成完整破解

**最大障碍**: signV3算法还原 (需要ARM64逆向能力)

---

*创建时间: 2026-05-28*
*预计完成: 2026-06-07*
