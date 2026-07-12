# 烛龙·后量子迁移治理平台 — 主机 Agent 安装手册

> 适用版本：v1.1.0（含后量子识别引擎 + 主机 Agent 全量密码学发现）
> 二进制：`zhulong-pqm-agent`（纯 Go 免 CGO 单文件，无运行时依赖）

---

## 1. 主机 Agent 是什么

Agentless 网络扫描只能看到「运行后端那台机器网络可达」的目标；仅监听 `127.0.0.1`、被防火墙挡在外、或在隔离内网的密码使用点它够不着。**主机 Agent 在目标主机本地运行**，把 Agentless 拿不到的密码学使用点采集后回报平台。

**全程只读**——绝不修改目标主机任何文件、进程或配置。

### 采集的五类使用点

| 模块 | 采集内容 | 层级 |
|---|---|---|
| **① 进程×加密库映射**（核心） | 读 `/proc/<pid>/maps` 找出每个进程实际加载的密码库，判定该库**是否具备后量子能力**（如「nginx 加载 OpenSSL 3.5.0」=后量子就绪 D1≤15；「加载 OpenSSL 3.0.2」=经典 D1=70）。同 soname 歧义（`libcrypto.so.3` 可能是 OpenSSL 或铜锁 Tongsuo）用版本串/符号消歧 | L4 |
| ② 监听服务 TLS 握手 | 读 `/proc/net/tcp{,6}` 枚举 LISTEN 端口（含仅绑 `127.0.0.1`），本地握手取证书/协商组/后量子态 | L1 |
| ③ 磁盘证书 | `/etc/ssl`、`/etc/pki`、nginx、`/opt/*/etc` 等目录下的 `.pem/.crt/.cer`，解析算法/位数/指纹/到期 | L2 |
| ④ SSH 主机密钥 | `/etc/ssh/*_key.pub` 的算法与位数（弱 DSA/RSA-1024 会被识别并按高风险评分） | L2 |
| ⑤ 内核算法 + 包清单 | `/proc/crypto` 内核算法；`dpkg`/`rpm` 已装密码库包及版本（判 PQC 能力） | L4 |

> 平台会对每条使用点自动补五维评分、后量子安全态、HNDL 标记，并盖 `ReportedBy=<agentId>` 归属到具体主机。

---

## 2. 前置条件

- **操作系统**：Linux（x86_64 或 aarch64/信创鲲鹏·飞腾）。非 Linux 主机上进程/监听/内核发现自动跳过，证书与 SSH 主机密钥仍可采。
- **权限**：普通用户即可运行（只读采集）。**建议 root 或 `CAP_SYS_PTRACE`**——否则 `/proc/<pid>/maps` 只能读到当前用户自己的进程，看不全其它服务。
- **网络**：目标主机能访问平台地址（默认 `http://<平台>:8099`，或经反代的 `/api/`）。
- **无运行时依赖**：单个静态二进制，不需要 curl/python/openssl。（仅 rpm 系的包清单会调用系统 `rpm`，装了才采、没有则跳过。）

---

## 3. 三步安装

### 第 1 步：管理员注册 Agent，取一次性 API Key

在控制台或用 API 注册。**apiKey 仅在注册时返回一次，平台只存哈希，此后无法再取**——请立即保存。

```bash
# 管理员先登录拿 token
TOKEN=$(curl -s -X POST http://<平台>:8099/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<管理员密码>"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# 注册一个 Agent（kind: host 主机发现 / probe 抓包探针 / both）
curl -s -X POST http://<平台>:8099/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"hostname":"web-01","kind":"host","labels":["生产","DMZ"],"os":"UOS/DAS-OS"}'
# → {"agent":{"agentId":"agent-3419ff80",...},"apiKey":"zpqm-agent-fce3ae2a....","note":"..."}
```

记下 `apiKey`（形如 `zpqm-agent-...`）。

### 第 2 步：把二进制拷到目标主机

从交付包 `bin/` 里按架构取：

| 架构 | 文件 |
|---|---|
| x86_64 | `zhulong-pqm-agent-linux-amd64` |
| aarch64（鲲鹏/飞腾） | `zhulong-pqm-agent-linux-arm64` |

```bash
# 例：scp 到目标主机并改名
scp bin/zhulong-pqm-agent-linux-amd64 web-01:/usr/local/bin/zhulong-pqm-agent
ssh web-01 'chmod +x /usr/local/bin/zhulong-pqm-agent'
```

### 第 3 步：运行

```bash
# 跑一次即退出（--once 是默认）
ZPQM_AGENT_SERVER=http://<平台>:8099 \
ZPQM_AGENT_KEY=zpqm-agent-fce3ae2a.... \
  /usr/local/bin/zhulong-pqm-agent --once
```

输出示例：

```
发现完成：共 27 条密码学使用点
[批次 0-27] 新建 27 / 更新 0（Agent=agent-3419ff80）
上报完成：共 27 条，新建 27 / 更新 0
```

到控制台「密码使用点清单」按 **来源 = agent** 筛选即见本机采集的资产（已评分、已按 `ReportedBy` 归属）。**重复运行幂等**——同一事实只更新不新增。

---

## 4. 参数与环境变量

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `--server` | `ZPQM_AGENT_SERVER` | `http://127.0.0.1:8099` | 平台地址 |
| `--key` | `ZPQM_AGENT_KEY` | （必填） | 注册时下发的 apiKey |
| `--once` | — | `true` | 跑一次即退出 |
| `--interval` | `ZPQM_AGENT_INTERVAL` | `0` | >0 时常驻，每 N 秒采一次（覆盖 `--once`） |
| `--fsroot` | `ZPQM_AGENT_FSROOT` | `/` | 文件系统根（容器/测试时可指向挂载点） |
| `--ssh-dir` | — | `/etc/ssh` | SSH 主机密钥目录 |
| `--insecure` | — | `false` | 跳过平台 TLS 证书校验（自签演示环境用） |

---

## 5. 常态化采集（systemd timer）

一次性单元 + 定时器，每小时采一次：

`/etc/systemd/system/zhulong-pqm-agent.service`
```ini
[Unit]
Description=Zhulong PQM Host Agent (once)
After=network-online.target

[Service]
Type=oneshot
Environment=ZPQM_AGENT_SERVER=http://<平台>:8099
Environment=ZPQM_AGENT_KEY=zpqm-agent-....
ExecStart=/usr/local/bin/zhulong-pqm-agent --once
# 只读采集，最小权限即可；如需看全进程加载库，去掉 NoNewPrivileges 并保留 root
```

`/etc/systemd/system/zhulong-pqm-agent.timer`
```ini
[Unit]
Description=Run Zhulong PQM Host Agent hourly

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zhulong-pqm-agent.timer
systemctl list-timers | grep zhulong   # 查看下次触发
journalctl -u zhulong-pqm-agent.service --no-pager | tail   # 查看采集日志
```

> 也可直接 `--interval 3600` 让单进程常驻（无需 timer）。

---

## 6. 安全说明

- **只读**：Agent 不写目标主机任何东西；不需要、也不应给写权限。
- **凭据**：`apiKey` 明文只在注册时出现一次；平台只存 SHA-256 哈希。放进 systemd `Environment=` 或受限权限的 env 文件（`chmod 600`）。
- **撤销**：主机下线或 Key 泄露，管理员 `POST /api/v1/agents/:id/revoke`，该 Key 立即失效。
- **受限通道**：Agent 用 `X-Agent-Key` 走独立的 `/api/v1/agent/*` 上报端点，**不发放用户 JWT、不触及用户权限面**，只能上报、不能读写平台其它资源。
- **归属可审计**：每次上报更新 Agent 的 `LastSeenAt`，落审计日志（`agent.ingest`）。

---

## 7. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 进程×库只采到很少几条 | 非 root 只能看自己的进程；用 root 或授 `CAP_SYS_PTRACE` 跑 |
| `401 Agent 凭据无效或已撤销` | key 错或已 revoke；重新注册取新 key |
| 非 Linux 主机采集条数少 | 进程/监听/内核发现仅 Linux；证书与 SSH 密钥仍会采 |
| 某库判成「同 soname 歧义/经典」 | 该 `.so` 里没扫到清晰版本串（如 `libcrypto.so.3` 未含 `OpenSSL 3.x` 字样）；保守判经典，可人工在清单里确认 |
| 重复运行会不会刷重复资产 | 不会。网络端点按 host:port、证书按指纹、主机事实按 `Agent+名称+算法` 合成锚点去重，重复运行只更新 |
| 自签演示环境 TLS 校验失败 | 加 `--insecure` |

---

## 8. 探针模式（role=probe，分布式抓包）

同一二进制加 `--role=probe` 即变**旁路抓包探针**：在镜像口/SPAN 口实时抓包，边缘解析出 TLS+后量子观测上报，**只回传观测、不回传原始包**（省带宽+隐私）。

```bash
# 需 root 或 CAP_NET_RAW（AF_PACKET 原生抓包）；无权限自动回退宿主机 tcpdump
sudo ZPQM_AGENT_SERVER=http://<平台>:8099 ZPQM_AGENT_KEY=zpqm-agent-.... \
  ./zhulong-pqm-agent --role=probe --iface=eth0 --duration=60

# 或授权后免 sudo：
sudo setcap cap_net_raw+ep ./zhulong-pqm-agent
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--iface` | 全部/any | 抓哪张网卡（镜像口） |
| `--duration` | 30 | 抓包时长（秒） |
| `--max-packets` | 100000 | 抓包数上限 |
| `--bpf` | `tcp` | tcpdump 回退时的过滤表达式 |
| `--capture-mode` | `auto` | `auto`(AF_PACKET 优先→tcpdump 回退)/`afpacket`/`tcpdump` |

常驻：`--interval 300` 每 5 分钟抓一轮。多探针=在各旁路点各部署一个 `--role=probe` 实例（各自注册取 Key）。到「密码使用点清单」按来源=agent 看，含协商组/后量子态。

> 服务端集中下发抓包任务（按网段分发给多探针、租约领任务）是下一里程碑 M-D2；本版探针为配置驱动。
