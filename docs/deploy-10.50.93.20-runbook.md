# 部署 Runbook — 10.50.93.20（内网自服务，免 nginx）

> v1.1.0 交付包：`deploy/zhulong-pqm-1.1.0.tar.gz`（18.8MB，含后端+主机Agent双架构+前端）
> 目标机 10.50.93.20 = 安恒 DAS-OS 内网机，**自服务前端（ZPQM_STATIC_DIR，无 nginx）**。

## ⚠️ 为什么这一步需要你手动执行

- 本机（开发 Mac）**无 10.50.93.20 的免密 SSH**，且该机 sshd 有 **faillock + PerSourcePenalties**——反复试连会把机器/来源 IP 封掉。故未由我自动传输。
- 该机**无免密 sudo**，`install.sh` 的特权步骤（systemd/写 /opt）须你本人执行。
- 传输/安装请**复用一条 SSH 连接**（ControlMaster），避免多次握手触发封禁：

```bash
# 在你的机器 ~/.ssh/config 里为该机配 ControlMaster（连一次，后续复用）
cat >> ~/.ssh/config <<'EOF'
Host das20
  HostName 10.50.93.20
  User <你的账号>
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 10m
EOF
ssh das20 true   # 首次建连（输一次密码，后续命令复用不再握手）
```

## 方式 A：自服务（推荐，免 nginx，可非特权跑）

```bash
# 1) 传包（复用 das20 连接）
scp deploy/zhulong-pqm-1.1.0.tar.gz das20:/tmp/

# 2) 目标机上解包到自服务目录（示例 ~/zhulong-pqm，无需 root）
ssh das20 'cd ~ && tar xzf /tmp/zhulong-pqm-1.1.0.tar.gz && ln -sfn zhulong-pqm-1.1.0 zhulong-pqm'

# 3) 选架构后端二进制（信创飞腾/鲲鹏用 arm64，x86 用 amd64）
ssh das20 'cd ~/zhulong-pqm && cp bin/zhulong-pqm-linux-$(uname -m | sed "s/x86_64/amd64/;s/aarch64/arm64/") ./zhulong-pqm && chmod +x zhulong-pqm'

# 4) 起后端：ZPQM_STATIC_DIR 指向 web/ → 后端自服务前端(/pqm/ SPA 回退)
#    ⚠ 生产务必显式设 JWT/加密密钥(否则进程级随机、重启全体 token 失效)
ssh das20 'cd ~/zhulong-pqm && \
  ZPQM_JWT_SECRET="$(openssl rand -hex 32)" \
  ZPQM_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  ZPQM_STATIC_DIR="$HOME/zhulong-pqm/web" \
  nohup ./zhulong-pqm > ~/zhulong-pqm/pqm.log 2>&1 &'

# 5) 验证
ssh das20 'sleep 2 && curl -s http://127.0.0.1:8099/api/v1/healthz'   # {"status":"ok"}
```

浏览器访问 `http://10.50.93.20:8099/pqm/`（若走既有反代则按其前缀）。默认账号 `admin/admin@1234`（首次登录后请改密）。

> 首启自动建库 + 植入种子（7 预设画像、30 规则库）。DB 落 `~/zhulong-pqm/zhulong-pqm.db`。

## 方式 B：systemd（需 root/sudo，交付包自带 install.sh）

```bash
ssh das20 'cd ~/zhulong-pqm && sudo ./install.sh'   # 装 systemd 单元 + 随机 JWT + system user
# install.sh 默认配 nginx；该机若不用 nginx，改用方式 A 或按 install.sh 内注释走 ZPQM_STATIC_DIR
```

## 部署后：在该机装主机 Agent（验证进程×库发现）

```bash
# 1) 注册 Agent 取 apiKey（在能访问平台的机器上）
TOKEN=$(curl -s -X POST http://10.50.93.20:8099/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin@1234"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
curl -s -X POST http://10.50.93.20:8099/api/v1/agents -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"hostname":"das-93-20","kind":"host","os":"DAS-OS"}'
#   记下返回的 apiKey

# 2) 目标机就是本机：直接用 arm64/amd64 agent 二进制跑（root 看全进程）
ssh das20 'cd ~/zhulong-pqm && cp bin/zhulong-pqm-agent-linux-$(uname -m | sed "s/x86_64/amd64/;s/aarch64/arm64/") ./zpqm-agent && chmod +x zpqm-agent && \
  sudo ZPQM_AGENT_SERVER=http://127.0.0.1:8099 ZPQM_AGENT_KEY=<刚才的apiKey> ./zpqm-agent --once'
```

到「密码使用点清单」按 **来源=agent** 看本机采集（进程×库/证书/SSH主机密钥/内核算法）。详见《主机 Agent 安装手册》。

## 回滚 / 停机

- 方式 A：`ssh das20 'pkill -f "zhulong-pqm$"'`（停后端进程）；删 `~/zhulong-pqm*` 即彻底清除。
- 方式 B：`ssh das20 'sudo ./uninstall.sh'`。

## 排错

| 现象 | 处理 |
|---|---|
| 页面资源 404 白屏 | 前端子路径部署须 base=/pqm/；本包已构建为 /pqm/。若挂在别的前缀需重构建改 vite base |
| 重启后所有人要重登 | 没显式设 `ZPQM_JWT_SECRET`，进程级随机密钥重启即变——务必设固定值 |
| :8099 外部访问不到 | 检查目标机防火墙/安全组是否放行 8099（或只经反代访问） |
| SSH 连不上/被封 | faillock 触发；等惩罚窗口过、用 ControlMaster 复用单连接、别并发多次连 |
