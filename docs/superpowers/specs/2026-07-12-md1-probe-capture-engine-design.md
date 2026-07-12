# 设计：M-D1 分布式抓包探针拓包引擎（配置驱动）

- 状态：草案（brainstorm 已批准，待 spec 复核）
- 日期：2026-07-12
- 里程碑：M-D 的第一步（M-D1 拓包引擎；M-D2 服务端任务调度+控制台 UI 留下一轮）
- 依赖：M-A（PQC 识别引擎 + `scan.ParsePCAP`）、M-B（Agent 身份 + `/agent/assets/batch` 受限上报）、M-C（`backend/cmd/agent/` 二进制 + `report.go`）均已并入 main

## 0. 背景与目标

用户诉求②：现在网络抓包是被动上传分析，真实环境应能**分派多个小探针主动抓取网络流量**。M-A 已让平台认识后量子握手，M-B 给了 Agent 专属身份，M-C 建了主机 Agent 二进制。M-D1 在同一二进制上加 `--role=probe`：探针在旁路/镜像口**实时抓包**，边缘就地解析出密码学观测，经 M-B 受限通道上报——无需人工上传 pcap。

**本轮目标**：探针拓包引擎能跑通「抓包 → 边缘解析 → 上报」，配置驱动（本地参数告诉它抓哪张网卡/过滤/时长）。
**非目标（留 M-D2）**：服务端 CaptureTask 模型、控制台建任务、按 Labels/网段分发给多探针、探针轮询 `GET /agent/tasks` 租约领任务。「分派多个探针」本轮=运维在各旁路点手动部署多个 `--role=probe` 实例。

## 1. 架构与数据流

全部在 `backend/cmd/agent/`，最大化复用 M-A 的 `scan.ParsePCAP` 与 M-C 的 `report.go`。

```
AF_PACKET 原生套接字 (x/sys/unix, Linux 首选)  ┐
   或 tcpdump -w - 管道 (回退)                ├─→ pcap 字节流 ─→ scan.ParsePCAP()
                                              ┘        (M-A: L2/L3/TCP重组/TLS+PQC解析全复用)
                                                           │
                                                           ▼
                                                []TLSObservation
                                                (host/port/version/cipher/kexGroup/kexSafety/certFP/sni)
                                                           │  映射
                                                           ▼
                                                []model.CryptoAsset (Endpoint=host:port, Layer=L1, Source=agent)
                                                           │  复用 report.go reportAssets()
                                                           ▼
                                                POST /api/v1/agent/assets/batch (X-Agent-Key → ReportedBy)
```

### 关键设计点

1. **最大复用**：抓到的 L2 帧包成标准 pcap 格式（AF_PACKET 给裸以太帧 → 加 pcap 全局头[linktype=1 Ethernet]+每帧记录头；tcpdump `-w -` 本就输出 pcap），直接喂 `scan.ParsePCAP`。M-A 已验证的 TLS+PQC 解析/TCP 重组/GREASE 跳过/HRR 权威组处理全部复用，探针侧不重写解析。
2. **边缘只回传观测**：探针把解析出的观测转成 `CryptoAsset` 上报，**绝不回传原始 pcap 字节**（省带宽 + 隐私）。离开主机的只有握手元数据（host/port/协商组/证书指纹等）。
3. **抓包边界护栏**：`--duration`（秒）或 `--max-packets` 封顶；沿用 `ParsePCAP` 既有的 `maxPcapPackets/maxFlows/maxReassembly` 护栏 + `looksTLS` 只跟 TLS 握手起始的流。cBPF 内核级过滤（`tcp[((tcp[12]&0xf0)>>2)]=0x16`）作为后续性能优化，v1 靠应用层 `looksTLS` + 护栏。

## 2. 组件与文件划分

### 新增（`backend/cmd/agent/`）

- **`capture.go`** — 抓包编排 + 机制选择。
  - `Capture(cfg *Config) ([]byte, error)`：选机制 → 抓 → 返回 pcap 字节流。
  - 选择逻辑：`--capture-mode` = `auto`（默认）/`afpacket`/`tcpdump`。
    - `auto`：Linux 且能开 AF_PACKET 套接字 → afpacket；否则（EPERM 无 CAP_NET_RAW、或非 Linux）→ tcpdump（若 PATH 有）；都不行 → 清晰错误。
    - `afpacket` 强制：非 Linux/无权限直接报错不回退。
    - `tcpdump` 强制：直接走 tcpdump。
  - `wrapPcap(frames [][]byte) []byte`：裸以太帧数组 → 标准 pcap 字节（全局头 magic 0xa1b2c3d4 + linktype 1 + 每帧记录头[ts/caplen/origlen]）。**纯函数，可单测**。

- **`capture_afpacket.go`**（`//go:build linux`）— `captureAFPacket(cfg) ([]byte, error)`：`unix.Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` → 可选 `Bind` 到 `--iface`（不指定则全网卡）→ 循环 `Recvfrom` 读裸帧 → 到 `--duration` 或 `--max-packets` 停 → `wrapPcap`。读超时用 `SetsockoptTimeval(SO_RCVTIMEO)` 让 duration 可控。

- **`capture_stub.go`**（`//go:build !linux`）— `captureAFPacket` 返回 `errAFPacketUnsupported`（让 `auto` 回退 tcpdump、`afpacket` 强制报错）。保证 macOS 编译+测试。

- **`capture_tcpdump.go`** — `captureTcpdump(cfg) ([]byte, error)`：`exec.Command("tcpdump","-i",iface,"-w","-","-c",maxPackets,"-U",bpf)` 读 stdout 管道拿 pcap 字节。`--duration` 用 `context.WithTimeout` + `exec.CommandContext` 到时杀进程。BPF 默认 `"tcp"`；`--bpf` 覆盖。

- **`probe.go`** — 探针主流程 `runProbe(cfg) error`：`Capture` → `scan.ParsePCAP` → `observationsToAssets(obs, hostname)` → `reportAssets`（复用 M-C）。`observationsToAssets` 把 `scan.TLSObservation` 转 `model.CryptoAsset`（`Endpoint=host:port`、`Layer=L1`、`Exposure=internal`、填 `KexGroup/KexSafety`、`AuthSafety=cryptoref.AuthSafetyForAlgo(algo)`、`Algorithm/KeySize/CertFingerprint/Protocol`）。0 观测 → 上报 0 条正常退出。

### 改

- **`config.go`** — 加字段 + flag/env：`Iface`(`--iface`/`ZPQM_AGENT_IFACE`, 默认空=全网卡)、`Duration`(`--duration`/`ZPQM_AGENT_DURATION`, 默认 30 秒)、`MaxPackets`(`--max-packets`, 默认 100000)、`BPF`(`--bpf`, 默认 `tcp`)、`CaptureMode`(`--capture-mode`, 默认 auto)。
- **`main.go`** — 按 `cfg.Role` 分派：`host`（现有 5 路发现）/ `probe`（新 `runProbe`）。

## 3. 错误处理

- **0 包非错**：网卡无 TLS 流量→上报 0 条正常退出，日志提示。
- **权限不足**（AF_PACKET EPERM）：`auto` 静默回退 tcpdump；`afpacket` 强制则报可操作错误：`"AF_PACKET 需 CAP_NET_RAW：setcap cap_net_raw+ep <binary> / 或 --capture-mode=tcpdump / 或 sudo"`。
- **tcpdump 缺失**：`"未找到 tcpdump，且 AF_PACKET 不可用；请装 tcpdump 或授 CAP_NET_RAW"`。
- **抓包/解析异常**：不 panic（`ParsePCAP` 已守界）；单批上报失败沿用 `report.go` 的错误返回（不吞错）。

## 4. 测试（mac 可跑，不需真网卡/root）

- **`capture_test.go`**：
  - `wrapPcap` 往返：造几段裸以太帧（复用 M-A pcap_test 的 TLS 帧 builder 思路，含 ClientHello/ServerHello 选中 0x11EC 的字节）→ `wrapPcap` → `scan.ParsePCAP` 应解出 hybrid 端点（`KexGroup=X25519MLKEM768`）。这是 afpacket 真实路径的核心正确性保证（抓帧→加头→解析）。
  - `observationsToAssets` 映射：`TLSObservation{KexGroup:"curveSM2MLKEM768",KexSafety:"hybrid",...}` → `CryptoAsset` 字段正确（Endpoint/Layer=L1/Source=agent/KexSafety 保留/AuthSafety 由算法推导）。
  - `capture-mode` 选择：stub 下（`!linux` 构建标签在 mac 生效）`afpacket` 强制 → unsupported 错误；`auto` → 探测 tcpdump 分支。
- **交叉编译**：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 go build ./cmd/agent` 双架构必过（AF_PACKET 真实路径的编译保证）。
- **手动真机验收**（文档记录，需 root/CAP_NET_RAW，留部署环境）：起本地 TLS 服务 → `--role=probe --iface=lo --duration=10` 抓 loopback → 平台见 source=agent 观测。

## 5. 受影响文件清单

- 新增：`backend/cmd/agent/{capture.go, capture_afpacket.go, capture_stub.go, capture_tcpdump.go, probe.go, capture_test.go}`
- 改：`backend/cmd/agent/{config.go, main.go}`
- 文档：更新 `docs/主机Agent安装手册.md` 加「探针模式（role=probe）」一节；`CLAUDE.md` 架构地图补 probe。
- 后端：**零改动**（复用现有 `/agent/assets/batch`、`scan.ParsePCAP`、`cryptoref`）。

## 6. 约束

- **纯 Go 免 CGO 硬约束**：AF_PACKET 用 `golang.org/x/sys/unix`（v0.41.0 已在 go.mod，已验证 linux amd64/arm64 CGO_ENABLED=0 交叉编译通过）；tcpdump 走 `exec`（允许，二进制仍纯 Go）。不引入 libpcap/gopacket 等 CGO 依赖。
- 复用优先：不重写任何 TLS/pcap 解析——一律经 `scan.ParsePCAP`。
- 上报只出不回原始包（隐私）。commit 前缀 `feat(agent):`，中文。
