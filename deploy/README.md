# 烛龙 PQM 私有化部署

把后端（Go 二进制）+ 前端（静态站点）打成一个 tar.gz，在目标机一键安装为 systemd 服务并经 nginx 对外提供。后端用纯 Go SQLite（免 CGO），可直接交叉编译 amd64 / arm64（信创 鲲鹏/飞腾），目标机无需装 Go/Node。

## 目录

```
deploy/
├── build.sh                 开发机构建（后端双架构 + 前端）→ dist/
├── package.sh               dist/ → zhulong-pqm-<版本>.tar.gz
├── install.sh               目标机安装（root）
├── uninstall.sh             卸载（--purge 连数据一起删）
├── systemd/zhulong-pqm.service
├── nginx/zhulong-pqm.conf
└── config/zhulong-pqm.env   运行配置模板（JWT 密钥占位）
```

## 一、开发机：构建并打包

前置：Go 1.23+、Node 18+。

```bash
cd deploy
./build.sh                 # 交叉编译 linux amd64+arm64 + vite 生产构建
VERSION=1.0.0 ./package.sh # 产出 zhulong-pqm-1.0.0.tar.gz
```

## 二、目标机：安装（Linux，需 root）

```bash
tar xzf zhulong-pqm-1.0.0.tar.gz
cd zhulong-pqm-1.0.0
sudo ./install.sh          # 自动按 CPU 架构选 amd64/arm64
```

安装内容与布局：

| 路径 | 用途 |
|---|---|
| `/opt/zhulong-pqm/bin/zhulong-pqm` | 后端二进制 |
| `/opt/zhulong-pqm/web/` | 前端静态站点（nginx 根） |
| `/var/lib/zhulong-pqm/zhulong-pqm.db` | SQLite 数据库（服务用户可写） |
| `/etc/zhulong-pqm/zhulong-pqm.env` | 运行配置（首装自动生成随机 JWT 密钥） |
| `/etc/systemd/system/zhulong-pqm.service` | systemd 单元（专用系统用户、安全加固） |
| `/etc/nginx/conf.d/zhulong-pqm.conf` | nginx 站点（静态 + `/api` 反代到 127.0.0.1:8099） |

安装后：浏览器访问目标机 `http://<IP>/`，默认账号 **admin / admin@1234**（**首次登录请立即改密**）。

## 三、运维

```bash
systemctl status zhulong-pqm           # 状态
journalctl -u zhulong-pqm -f           # 日志
systemctl restart zhulong-pqm          # 重启
```

- **升级**：在目标机重新跑 `sudo ./install.sh`（新版交付包）。二进制与前端被覆盖，`/var/lib`(数据库) 与 `/etc`(含 JWT 密钥) **不被覆盖**。
- **卸载**：`sudo ./uninstall.sh`（保留数据）或 `sudo ./uninstall.sh --purge`（连数据/配置一并删除）。

## 四、安全与合规提示

- 后端监听 `0.0.0.0:8099`，对外仅应暴露 nginx（80/443）。**建议防火墙仅放行回环**访问 8099：
  `firewall-cmd --add-rich-rule='rule family=ipv4 source address=127.0.0.1 port port=8099 protocol=tcp accept'` 或等价 iptables 规则。
- 生产 JWT 密钥由 `install.sh` 随机生成，勿沿用开发默认值。
- **HTTPS / 国密**：`nginx/zhulong-pqm.conf` 含 443 TLS 示例；信创/密评场景可换 Tengine+babassl 等支持国密 TLCP(SM2) 的 nginx 与 SM2 证书。
- RBAC：内置 admin/operator/viewer；写操作限 operator/admin，用户管理限 admin，敏感操作留审计（控制台「审计日志」可查/导出）。

## 五、信创适配

- arm64 二进制覆盖鲲鹏/飞腾；麒麟/统信 OS 上 systemd + nginx 路径一致。
- 全栈无外部服务依赖（数据库为内嵌 SQLite），适合离线/内网一体机交付。如需更高并发或集中存储，可后续将 DB 切换为达梦/人大金仓（需后端增加方言适配）。
