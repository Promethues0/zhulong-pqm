# 设计：PQC 识别引擎 + 分布式密码学发现（Zhulong PQM 后量子迭代）

- 状态：草案（brainstorm 已批准，待 spec 复核）
- 日期：2026-07-11
- 范围：四个可独立交付的子项目，按依赖顺序推进
- 验收锚点：`~/Desktop/VPN客户端后量子抓包.pcapng`（含 X25519MLKEM768 与铜锁 SM2 混合组的真实握手）

---

## 0. 背景与问题陈述

平台当前在三处对后量子（PQC）**视而不见**，即便流量里真的用了 PQC：

1. **被动流量识别丢信号**：`backend/internal/scan/pcap_tls.go` 只解析密码套件与证书，从不解析 TLS 1.3 的 `supported_groups`(0x000a) 与 `key_share`(0x0033) 扩展——而 TLS 1.3 的密钥交换（也就是所有 PQC KEM）恰恰全在这两个扩展里。验收包里到 `:443` 协商成功了 `X25519MLKEM768`(0x11EC)、到 `:1443` 协商成功了铜锁 SM2 混合组(0x11EE)，平台却只记录 "TLS1.3 / AES-GCM"。
2. **评分把 PQC 打成不安全**：`backend/internal/scoring/scoring.go:248-271` 的 `deriveD1` 没有 PQC 分支，ML-KEM/ML-DSA/混合组落到 `default`（第 269 行）得 D1=70，按经典 ECC 处理；`optionsD1`(118-124) 也没有 PQC 手工档；CBOM 的 `NISTQuantumSecurityLevel`(cbom.go:71) 声明了从不填。全代码库里 PQC 只作为规则引擎的**排除项**（"长得像 PQC 就不报漏洞"，rules.go:84/176/123），从来不是可建档的**正面事实**。
3. **主动扫描拿不到协商组**：`tls_scanner.go` 用 `crypto/tls` 真握手，但 Go 的 `ConnectionState` 不暴露协商的命名组，所以主动扫描侧同样看不到 PQC。

同时，发现能力薄弱：主机 Agent 是 81 行 bash PoC（只报本机证书/SSH 主机密钥/openssl 版本，且拿 admin 密码换 token）；网络侧只能人工上传 pcap，没有任何远程探针/分布式抓取机制。

## 0.1 目标

- **G1**：平台能从被动流量、主动扫描、主机 Agent、分布式探针四个来源，正确识别每个使用点的**量子安全态**（KEX 维 + 认证维），并正确评分、正确标记 HNDL。
- **G2**：主机 Agent 从"报四样东西"升级为全量密码学发现（进程/OS/数据库/配置四个面）。
- **G3**：具备分派多个探针主动抓取网络流量的能力（当前只能被动上传 pcap）。
- **G4**：识别引擎认识铜锁/openHiTLS/pqmagic 等国密 PQC 线的算法与私有 TLS 码点，而非只认 IANA 标准。

## 0.2 非目标（本轮）

- 不做真实的 PQC 密码运算/完整密钥封装握手（主动探测用"枚举式" HelloRetryRequest 反射，无需算 KEM）。验收级真握手留作后续增强。
- 不做 Windows 主机 Agent 的深度采集（本轮聚焦 Linux 信创；Windows 留占位）。
- 不重写去重/建档主链路，只在其上增量加字段与分支。

---

## 1. 贯穿层：CryptoAsset 双维量子安全建模（KEX × 认证）

这是四个子项目共享的地基。密钥交换与身份认证在后量子迁移里是**两条独立的迁移线**：先迁 KEX 抵御"先抓后解（HNDL）"，认证迁移可以更晚。用一个合并的算法字符串无法表达"半迁移"，因此拆成两维。

### 1.1 数据模型变更（`backend/internal/model/model.go`，`CryptoAsset` 结构 631-679）

新增字段（均需加进 `db.Open` 的 `AutoMigrate` 清单，否则不建列）：

| 字段 | 类型 | 含义 | 取值 |
|---|---|---|---|
| `KexGroup` | string | 协商的密钥交换组名 | `X25519MLKEM768`/`SM2MLKEM768`/`x25519`/`secp256r1`/`""` |
| `KexSafety` | string | 交换维量子安全态 | `safe`/`hybrid`/`classical`/`na` |
| `AuthSafety` | string | 认证/签名维量子安全态 | `safe`/`hybrid`/`classical`/`na` |
| `ReportedBy` | string | 上报来源 Agent/探针 ID（归属） | `agent-7f3a`/`""` |

- `safe` = 纯 PQC（如纯 ML-KEM、ML-DSA）；`hybrid` = 经典+PQC 混合（X25519MLKEM768、SM2MLKEM768）；`classical` = 纯经典（X25519/ECDH/RSA/SM2）；`na` = 该维不适用（如裸证书文件无 KEX，或对称密钥）。
- 新增枚举常量组 `KexSafety*`/`AuthSafety*`（与现有 `Layer*`/`Source*` 同风格）。
- `Algorithm` 字段保留为人读摘要，可组合成 `"X25519MLKEM768 + ECDSA-P256"`。

### 1.2 评分改造（`backend/internal/scoring/scoring.go`）

- `deriveD1`（248-271）**前置** PQC 分支：`D1 = max(kexVuln, authVuln)`，仅对适用（非 `na`）维取值。映射：`safe→10`、`hybrid→15`、经典 ECC/EdDSA→70、RSA/经典 DH/SM2→90、弱 RSA≤1024/TLS1.0/1.1→100。经典分支保留现状作为兜底。
- `optionsD1`（118-124）新增两档手工选项：`"后量子KEM/签名(ML-KEM/ML-DSA)"→10`、`"混合(X25519+ML-KEM / SM2+ML-KEM)"→15`。
- `SuggestAlgo`（309-327）保持，但当资产已是 `safe`/`hybrid` 时建议文案改为"已达标/建议补齐认证维"。

### 1.3 HNDL 精准化（双维建模最大价值点）

- 现状：`HNDL = D2>=60 && D3>=60`（scoring.go:90）。
- 改为：`HNDL = D2>=60 && D3>=60 && KexSafety=="classical"`——**KEX 一旦 PQC/混合，HNDL 自动清除**，因为"先抓后解"打的就是密钥交换。这直接把"迁了 KEX"的收益量化出来。
- 报表/大屏可 `GROUP BY (KexSafety, AuthSafety)` 出三态：**经典**（两维都 classical）、**半迁移**（KEX∈{safe,hybrid} 且 Auth==classical）、**全迁移**（两维都 ∈{safe,hybrid}）。

### 1.4 CBOM 补全（`backend/internal/cbom/cbom.go`）

- `assetToComponent`（111-157）按安全态填 `NISTQuantumSecurityLevel`（PQC-L5/3/1、经典=0）与 `ClassicalSecurityLevel`。
- `cryptoFunctions`（197-210）补 PQC 分支：ML-KEM→`encapsulate`/`decapsulate`，ML-DSA/SLH-DSA→`sign`/`verify`。
- `primitiveOf`（171-188）补：ML-KEM→`kem`，ML-DSA/Dilithium/Falcon/SPHINCS+→`signature`。
- `parameterSetIdentifier` 与 `OID` 用 §2.1 的 `pqc_algo_table` 回填。

---

## 2. 子项目 A：PQC 识别引擎（先做，用验收包 pcap 端到端验收）

新增一个共享包 `backend/internal/cryptoref/`，把"码点/算法/库"三张字典与分类逻辑集中，供被动解析、主动扫描、Agent、探针复用。

### 2.1 三张引擎字典（由研究工作流回填）

> 以下三张表由 `pqc-crypto-lib-research` 工作流合成回填；此处先占位，落库前逐条核对来源。

**A. `named_group_table`**：TLS 命名组码点 → {name, kind(classical/hybrid/pqc), is_iana, size_hint, note}。
覆盖经典组、IANA 混合组（0x11EB/0x11EC/0x11ED）、遗留 Kyber 混合（0x6399/0x639A）、纯 ML-KEM、以及**铜锁/openHiTLS/pqmagic 的 SM2 国密混合组**与各家私有/实验/草案码点。

```
<待回填：named_group_table>
```

**B. `lib_detection_table`**：soname/包名 → {library, pqc_capable, pqc_since_version, note}，用于"进程×加密库映射"判某进程加载的库是否具备 PQC 能力。

```
<待回填：lib_detection_table>
```

**C. `pqc_algo_table`**：PQC 算法 → {kind(kem/signature), cbom_primitive, param_sets, oid, is_chinese_national, note}，用于评分与 CBOM。

```
<待回填：pqc_algo_table>
```

### 2.2 尺寸启发式兜底（关键鲁棒性）

注册表认不出的码点（铜锁私有码、未来新算法），用 `key_share` 字节数兜底判定：**client key_share > 1000 字节基本必是格基 KEM**（经典组：P-521=133B、x448=56B、x25519=32B）。因此即便 `0x11EE` 未在表中，也能凭 1249B 判为"疑似 PQC/混合"，`KexSafety=hybrid`（若同时含 ≤133B 的经典分量特征）或 `pqc`，并在 `note` 标"尺寸启发式判定，码点未确认"。

### 2.3 A2 被动解析补齐（`backend/internal/scan/pcap_tls.go`）

在 `tlsHandshake` 结构加 `offeredGroups []int`、`negotiatedGroup int`、`keyShareLens map[int]int`；在 `parseHello`（client 分支）后续解析扩展区：

- ClientHello：`supported_groups`(0x000a) → `offeredGroups`；`key_share`(0x0033) → 每组的 `keyShareLens`（拿尺寸做启发式）。
- ServerHello / **HelloRetryRequest**（ServerHello + 特殊 random `CF21AD74...`）：`key_share`(0x0033) 的 group 即**权威协商组** → `negotiatedGroup`。
- 经 `cryptoref` 分类 → `KexGroup`/`KexSafety`。协商组优先；只见 ClientHello 时记 `offeredGroups`+"客户端支持 PQC，协商结果未观测"。
- 所有解析沿用现有"不可信字节严格守界、遇截断安全返回不 panic"的写法。

### 2.4 A3 主动枚举探针（`backend/internal/scan/` 新增 `pqc_probe.go`）

自造 ClientHello 做**逐组枚举**，无需任何 PQC 密码运算：

- 构造 raw ClientHello：`supported_groups` 只放一个目标 PQC 组，**不带匹配 key_share**（或带 GREASE 占位）。
- 服务端若支持该组 → 回 **HelloRetryRequest 报出它要的组**（或直接 ServerHello 选中）；不支持 → `handshake_failure` alert 或选别的组。
- 复用 §2.3 的 ServerHello/HRR 解析拿 `negotiatedGroup`。逐组枚举出服务端 PQC 支持矩阵。
- 与现有 `crypto/tls` 真握手（拿证书/认证维）并行，结果合并进同一 `CryptoAsset`。
- 作为一个可选 `Scanner` 能力挂到现有 `runner`（`ScannerType` 增 `tls-pqc` 或作为 tls 扫描的增强步）。

### 2.5 A4 评分/CBOM/正面规则

- 落地 §1.2/§1.3/§1.4。
- 把 PQC 从排除项翻正为正面事实：`internal/db/seed_rules.go` 增 `R-*-PQC` 规则（识别到 PQC/混合部署即记一条"已迁移/已达标"证据），`rules.go` 增正面命中路径。规则库自检计数（当前强制 total=30）相应更新。

### 2.6 A 的验收（明确、可执行）

上传 `~/Desktop/VPN客户端后量子抓包.pcapng` 后，平台密码使用点清单应出现：
- `:443` 使用点：`KexGroup=X25519MLKEM768`、`KexSafety=hybrid`、`HNDL=false`（已缓解）、D1≤15。
- `:1443` 使用点：`KexGroup=SM2MLKEM768`（或"疑似铜锁 SM2 混合，尺寸启发式"）、`KexSafety=hybrid`。
- 纯经典 x25519 的那几条：`KexSafety=classical`，若数据敏感+长生命周期则 `HNDL=true`。
- 单测：新增 `pqc_probe_test.go`、扩 `pcap_test.go`，用验收包片段做黄金用例；`scoring_test.go` 加 PQC 画像断言。

---

## 3. 子项目 B：Agent/探针身份与上报契约（A 之后，B/C/D 共享）

现状：Agent 拿 admin 密码换 12h JWT，平台不知道"哪台机的哪个 Agent 报的"，也没有比 login 限流更细的入站控制。

### 3.1 数据模型

新增 `Agent` 模型：`{ID, AgentID(外部), Hostname, Kind(host/probe/both), Labels[], Version, Status(pending/active/revoked), CredHash, LastSeenAt, EnrolledAt}`（进 AutoMigrate）。

### 3.2 注册与凭据（告别 admin 密码）

- 管理员在控制台签发**注册令牌**（限时 TTL + 限用次数，`operator/admin` 权限）。
- Agent `POST /api/v1/agents/enroll`（带注册令牌）→ 换取**每 Agent 专属长期凭据**（agentID + secret，服务端只存 `CredHash`）。
- Agent 用专属凭据换**受限作用域 token**（新增 RBAC scope `agent`）：仅可访问 ingest（`assets/import/*`、`/assets`、新 `/assets/import/observations`）与领任务端点，**不可**访问 operator 全权面。
- 所有 ingest 落 `ReportedBy=<agentID>`。入站限流按 Agent 维度（复用现有 throttle）。

### 3.3 兼容

- 保留现有"用户 JWT 直接 ingest"通道（bash PoC 仍可用），新契约为增量、不破坏旧路径。

---

## 4. 子项目 C：主机 Agent 全量发现（纯 Go 免 CGO 单二进制）

bash PoC → **纯 Go 单二进制 `zhulong-pqm-agent`**，与后端同仓（`agent/` 目录改为 Go module 或纳入 backend module 的 `cmd/agent`），信创鲲鹏/飞腾可交叉编译。免 CGO 硬约束：只读 `/proc`、解析配置/包数据库、必要时 shell 调 `rpm`/`dpkg`。运行 `role=host`，四发现面全上：

### 4.1 进程×加密库映射（核心）

- 读 `/proc/*/maps` + `/proc/*/exe`，去重每进程实际加载的密码库（`libssl`/`libcrypto`/`libgnutls`/`libgcrypt`/`libnss`/`libhitls`/`libpqmagic`/铜锁）及版本。
- 用 §2.1 `lib_detection_table` 判"该进程能否 PQC"（如 openssl≥3.5 / 铜锁 / openHiTLS = 是）。
- 输出：使用点（`layer=L4`，`Algorithm=<库名+版本>`，`note=进程 pid/comm`）+ CBOM 组件。

### 4.2 监听服务实握手

- 纯 Go 读 `/proc/net/tcp{,6}` 枚举 LISTEN 端口（含仅 127.0.0.1，替代 `ss` 依赖）。
- 对每个监听口本地 TLS/SSH 握手，复用 A 的 PQC 识别拿协商组/套件/证书。

### 4.3 配置与磁盘证据

- 解析 nginx/apache/sshd_config/openssl.cnf/postgresql.conf/my.cnf 声明的协议·套件·曲线·证书路径；枚举磁盘证书/密钥文件。
- 配置声明与 §4.2 运行态不符时标 `drift`（如 sshd 配了 mlkem KEX 但进程未加载支持库）。

### 4.4 OS 与包清单

- `/proc/crypto` 内核算法；LUKS/dm-crypt 全盘加密（读 LUKS header magic / 解析 `/proc` 而非依赖 `cryptsetup`）。
- 包级密码库版本：`dpkg` 读 `/var/lib/dpkg/status`（纯 Go 可解析）；`rpm` shell 调 `rpm -qa`（保纯 Go 二进制）。→ CBOM。

### 4.5 Agent 交付形态

- 复用 §3 的注册/凭据；采集结果经受限 token 上报，带 `ReportedBy`。
- `deploy/` 增 Agent 的交叉编译与打包（linux amd64+arm64）。

---

## 5. 子项目 D：分布式抓包探针（同一二进制 `role=probe`）

### 5.1 抓包机制：AF_PACKET 原生套接字

- Linux 下用 `golang.org/x/sys/unix`（已是 go.sum 间接依赖，纯 Go 免 CGO）开 `AF_PACKET`/`SOCK_RAW` 套接字，挂 BPF 过滤只拓 TLS 握手（`tcp[((tcp[12]&0xf0)>>2)]=0x16` 一类）。
- 需 `root`/`CAP_NET_RAW`；无权限或非 Linux 时**回退**到 shell 调 `tcpdump -w -`（管道），Agent 只负责解析（用户批准的默认：AF_PACKET 优先）。

### 5.2 边缘就地解析（省带宽 + 隐私）

- 探针端复用 `scan.ParsePCAP` + A 的 PQC 解析，**只回传抽取出的观测**（`{host,port,sni,version,kexGroup,kexSafety,cipher,certFP,...}`），不回传原始 pcap。

### 5.3 拉取式任务分发（防火墙友好，探针只出不入）

- 探针轮询 `GET /api/v1/agents/tasks`（受限 token）领取抓包任务（网卡、BPF 过滤、时长、目标端点、速率），租约式（lease + 心跳续约，超时回收）。
- 结果 POST 到新端点 `POST /api/v1/assets/import/observations`（结构化观测批量入库，复用 `upsertAsset` 的 endpoint 去重）。
- 平台按 Agent `Labels`/网段把任务分发给多个探针。可复用 `ScanJob` 已有的闲置 `Schedule`/`NextRunAt`/`RateLimit` 字段承载任务。

---

## 6. 交付顺序、里程碑与依赖

```
A（识别引擎）──▶ B（身份契约）──▶ C（主机 Agent）──▶ D（分布式探针）
   │                                    │                  │
   └─ cryptoref 三字典被 C/D 复用 ───────┴──────────────────┘
```

- **M-A**：贯穿层数据模型 + cryptoref 三字典 + 被动解析补齐 + 主动枚举探针 + 评分/CBOM/正面规则。验收：pcap 端到端。
- **M-B**：Agent 模型 + 注册/受限凭据 + `ReportedBy` 归属 + agent scope RBAC。
- **M-C**：Go Agent 单二进制 + 四发现面 + 打包。
- **M-D**：AF_PACKET 抓包 + 边缘解析 + 拉取式任务 + observations ingest。

每个里程碑独立走：写实现计划（writing-plans）→ TDD 实现 → 多智能体三视角审查（对齐仓库既有惯例）。本设计文档批准后，**立即为 M-A 写实现计划开工**，M-B/C/D 设计已定、留作后续。

## 7. 风险与约束

- **纯 Go 免 CGO 是硬约束**（CLAUDE.md）：AF_PACKET 用 `x/sys/unix` 满足；rpm 走 shell；SQLite 保持 glebarez；不得引入 CGO 依赖。
- **私有码点漂移**：铜锁/openHiTLS 的私有码点可能随版本变；靠尺寸启发式兜底 + `cryptoref` 表可运行期扩展（考虑把 named_group_table 也做成可 seed 进 DB 的行，便于不重编译加码点——本轮先 Go 表 + 启发式，DB 化留后续）。
- **主动枚举探测的合规**：只对授权目标发探测 ClientHello，沿用现有扫描的授权/速率/SSRF 防护。
- **规则库自检**：新增 PQC 规则会改变 seed_rules 的强制计数断言，需同步更新。
- **端口/环境**：后端 :8099，勿与 :8088 混淆；字节跳动蓝 #165DFF 主题；vite base 双态坑。

## 8. 受影响文件清单（M-A 起）

- 新增：`backend/internal/cryptoref/named_groups.go`、`algorithms.go`、`lib_detect.go`（三字典 + 分类逻辑）；`backend/internal/scan/pqc_probe.go`（+`_test.go`）。
- 改：`model/model.go`（CryptoAsset 四字段 + 枚举）、`db/db.go`（AutoMigrate）、`scoring/scoring.go`（deriveD1/optionsD1/HNDL）、`cbom/cbom.go`（量子等级/primitive/functions）、`scan/pcap_tls.go`（扩展解析）、`scan/tls_scanner.go`（挂 PQC 探针）、`db/seed_rules.go`+`scan/rules.go`（正面 PQC 规则）、`scoring/scoring_test.go`/`scan/pcap_test.go`（PQC 用例）。
- 前端（M-A 尾）：Assets/RiskAssessment 列表与详情展示 KexGroup/双维安全态；大屏加"经典/半迁移/全迁移"分布。`frontend/src/api/types.ts` 镜像新字段。
