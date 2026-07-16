# 主动 PQC 枚举探针接线（tls-pqc 扫描器）设计

- 日期：2026-07-16
- 归属里程碑：M-A 遗留收尾（「主动 PQC 探针 `ProbePQCGroups` 尚无调用方」）
- 状态：设计已认可，待写实现计划

## 1. 背景与问题

M-A（PQC 识别引擎）已交付 `internal/scan/pqc_probe.go`：自造 ClientHello 逐组枚举，
用 HelloRetryRequest 逼服务端报出它选中的密钥交换组，无需任何 PQC 密码运算。
但该文件的 `ProbePQCGroups` **至今无调用方**，是 M-A 最终审查记录在案的非阻塞遗留。

根因：现有主动扫描器 `TLSScanner`（`internal/scan/tls_scanner.go`）用 Go 标准库
`crypto/tls` 做真握手——它能拿到证书链（认证维：KeyAlgo/KeySize/SigAlgo）、TLS 版本、
密码套件，但 **Go 标准库不暴露协商出的密钥交换组的稳定 API，更永不支持国密组
`curveSM2MLKEM768`(0x11EE)**。因此主动扫描在**密钥交换维（KexGroup/KexSafety）完全是瞎的**。

这正是 M-A 最终审查 I4 记录的洞的来源：「主动重扫无 KexGroup 会抹除被动发现的 hybrid」。
被动 pcap 解析（`pcap_tls.go`）能读出 KexGroup，但主动扫描读不出——两条发现路径能力不对等。

**本设计把 `ProbePQCGroups` 接线进一个新的组合式扫描器 `tls-pqc`**，让主动扫描
也能产出密钥交换维观测，补齐 PQC 识别能力，且不拖慢默认 tls 扫描。

## 2. 目标与非目标

### 目标
- 新增 opt-in 扫描器 `tls-pqc`：真握手拿证书 + 逐组枚举拿 PQC 支持矩阵，合并进同一 `ScanResult`。
- 枚举覆盖 cryptoref 表内**全部真实的 safe/hybrid 组**（含国密 0x11EE）。
- 前端建扫描任务可选扫描器类型（默认 tls 快扫 / tls-pqc 深挖 PQC）。

### 非目标（YAGNI）
- 不改默认 `tls` 扫描器的行为或速度（不给经典目标平白加连接开销）。
- 不新增发现方式 M-x（tls-pqc 仍是主动 TLS 握手，`Method()` 保持 M1）。
- 不动被动 pcap 解析路径（那条路已能读 KexGroup）。
- 不接线到监测复扫 / 调度器（那是另一层，超出本次范围）。
- 不做 PQC 签名算法（认证维 PQC）的主动探测——认证维已由证书链覆盖。

## 3. 架构

后端改 4 处 + 前端改 2 处。

### 3.1 `cryptoref.PQCGroupCodepoints()`（新导出函数，`named_groups.go`）

返回可枚举的 PQC/混合组码点白名单（`[]int`），供探针作枚举来源。

- **纳入**：`namedGroups` 表里所有 `kind` 为 `pqc` 或 `hybrid` 且**真实存在**的组：
  - 纯 ML-KEM：0x0200 MLKEM512 / 0x0201 MLKEM768 / 0x0202 MLKEM1024
  - 混合：0x11EB SecP256r1MLKEM768 / 0x11EC X25519MLKEM768 / 0x11ED SecP384r1MLKEM1024 /
    **0x11EE curveSM2MLKEM768（国密，铜锁 Tongsuo 8.5+）** / 0x6399 X25519Kyber768Draft00
- **排除**：0xFEFE curveSM2MLKEM768(draft-02)——仅作旧版铜锁的**时间指纹**，非真实可协商目标
  （表中 isIANA=false 且注释标为时间指纹）；GREASE 组（`IsGREASEGroup`）；一切经典组。
- **实现方式**：curated 显式码点清单，**不靠 isIANA 或 kind 语义自动推导**——因为
  0xFEFE 也是 hybrid kind 但必须排除，语义推导会误纳。清单在源码中显式列出并注释理由。
- 顺序即枚举顺序，也即命中后选主组的优先序（把互联网主流 0x11EC 与国密 0x11EE 排在前面）。

### 3.2 `internal/scan/tls_pqc_scanner.go`（新 `TLSPQCScanner`）

组合式扫描器，实现 `Scanner` 接口：

```
Scan(ctx, host, port):
  1. res, err := (&TLSScanner{}).Scan(ctx, host, port)   // 委托真握手拿证书/认证维/版本/套件
     err != nil → 直接返回 err（无证书=无资产，与现有语义一致：探测失败记 failed 结果）
  2. supported := ProbePQCGroups(host, port, cryptoref.PQCGroupCodepoints(), dialTimeout)
     （逐组枚举；单组连接失败视为不支持，不终止整体；探针内部已 continue 容错）
  3. if len(supported) > 0:
        primary := supported[0]                          // 表序第一个即主组（枚举顺序已按优先序）
        name, kind, _, _ := cryptoref.ClassifyGroup(primary)
        res.KexGroup = name
        res.KexSafety = cryptoref.SafetyFromKind(kind)
        // 全部支持组 + 主组写进 Raw（合并进既有 JSON 快照）与 EvidenceNote 留证
  4. return res, nil

Method() → model.MethodM1ActiveTLS   // 仍是 M1，主动 TLS 握手
Name()   → "tls-pqc"
```

- 探针沿用包级 `dialTimeout`（已由 `ZPQM_SCAN_TIMEOUT_MS` 可配）。
- `HitMatcher` 不额外实现——Runner 回落到通用 `MatchRules`，它已经会经
  `cryptoref.SafetyForGroupName(res.KexGroup)` 命中混合/PQC 判定（`rules.go:89/97`）。
- 组合优先复用而非改写 `TLSScanner`：默认 tls 扫描零回归。

### 3.3 `NewScanner` 分发（`scanner.go`）+ 常量（`model.go`）

- `model.go` 新增 `ScannerTLSPQC = "tls-pqc"`。
- `scanner.go` 的 `NewScanner` switch 增 `case model.ScannerTLSPQC: return NewTLSPQCScanner()`。
- 后端 `createScanReq.ScannerType` 与 `NewRunnerForJob` 已现成接受任意 scannerType，无需改动。

### 3.4 前端（`Discovery.vue` + `api/types.ts`）

- `ScanInput` 加可选 `scannerType?: string`。
- Discovery 新建扫描表单加扫描器 `a-select`：
  - `tls`（默认）— 「TLS 快扫（证书 + 套件）」
  - `tls-pqc` — 「TLS + PQC 深挖（枚举后量子组，较慢）」
  - `ssh` — 保留既有（若表单本就该暴露，顺带补；否则只加 tls/tls-pqc 两项，最小改动）
- `submit()` 透传 `scannerType`；默认不选即 tls，行为不变。

## 4. 数据流

```
用户建 tls-pqc 任务
  → POST /scans {scannerType:"tls-pqc"}
  → NewRunnerForJob(db,"tls-pqc") → NewScanner → TLSPQCScanner
  → 逐目标 Scan：真握手拿证书 + ProbePQCGroups 逐组枚举
  → ScanResult{KeyAlgo/SigAlgo/... , KexGroup:"curveSM2MLKEM768", KexSafety:"hybrid"}
  → runner.upsertAsset：effective KEX = res.KexSafety（观测层权威，FIX 2 路径）
  → deriveD1 走 hybrid 档 D1=15，EffectiveHNDL 据 KEX 清 HNDL
  → MatchRules 经 SafetyForGroupName(KexGroup) 命中混合/PQC 规则
```

关键：主动扫描现在**产出 KexGroup**，不再抹除、而是补齐密钥交换维，与被动 pcap 能力对等。

## 5. 错误与边界

- 真握手失败（连接拒绝/超时/非 TLS）：整体返回 err，Runner 记 failed 结果（现有路径）。
- 握手成功但探针全不支持（纯经典目标）：`KexGroup` 留空，`SafetyForGroupName("")` = na，
  不误判——经典目标 D1 由证书算法（认证维）经 deriveD1Classic 决定，符合预期。
- 探针单组连接被中间盒重置/超时：`ProbePQCGroups` 内部 continue，视为不支持该组，不影响其它组。
- 不可信响应字节：探针复用 `pcap_tls.go` 的 `parseHello`（严格守界、截断安全返回不 panic）。
- 授权/速率/SSRF：目标来自已过 `ParseTargets`（CIDR 展开上限）与设备端点 SSRF 校验的 job 目标，
  探针不引入新的目标来源。

## 6. 测试（TDD）

### 6.1 `cryptoref` 单测（`named_groups_test.go` 扩）
- `TestPQCGroupCodepoints`：返回集合**精确**等于预期白名单——
  含 0x11EE（国密）、0x11EC、0x0200-0x0202 等；**不含** 0xFEFE、任一 GREASE、任一经典组。

### 6.2 `internal/scan/tls_pqc_scanner_test.go`（新）
- `TestTLSPQCScanner_ProbeMergesKexGroup`：本地 `net.Listener` 罐装一个对目标组回
  HelloRetryRequest 选中该组的响应，断言 `probeOneGroup` / 扫描器把 KexGroup/KexSafety 填对。
- `TestTLSPQCScanner_UnsupportedGroup`：罐装 handshake_failure alert（0x15），断言判不支持、KexGroup 空。
- `TestTLSPQCScanner_RealHandshakeCarriesCert`：`httptest.NewTLSServer` 起真 TLS 服务，
  断言扫描结果同时带证书字段（KeyAlgo/CertFingerprint）——证明委托真握手这一步没丢。
  （httptest 服务器是经典 ECDSA/RSA，探针枚举 PQC 组会全不支持 → KexGroup 空，这本身也是
   「经典目标不误判」的验证。）

### 6.3 回归
- `go build ./... && go vet ./... && go test ./...` 全绿，7 预设画像断言不动。
- 前端 `npm run build`（vue-tsc）绿。

## 7. 验收

- 本地起后端，建一个 `scannerType:"tls-pqc"` 任务扫一个已知支持 PQC 的目标
  （或本地起罐装服务），资产清单出现 KexGroup/KexSafety 观测。
- 建一个 tls-pqc 任务扫纯经典目标，KexGroup 空、D1 由证书算法决定，不误判 hybrid。
- 默认 tls 任务行为、耗时与改动前一致（无回归）。
- 前端扫描表单可选 tls-pqc 且透传成功。

## 8. 影响面与风险

- 纯增量：新扫描器、新导出函数、前端一个下拉项；默认 tls 路径零改动。
- 纯 Go 免 CGO 约束不破（探针是 `net.Dial` + 手搓字节，无新依赖）。
- 成本：tls-pqc 每目标约 1 次真握手 + N（≈8）次短连接探测，受 `maxConcurrency=16` 约束，
  opt-in 故不影响默认扫描成本；文档/前端提示「较慢」，诚实告知。
