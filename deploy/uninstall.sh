#!/usr/bin/env bash
# 卸载烛龙 PQM。默认保留数据库与配置；加 --purge 一并删除数据与配置。
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo ./uninstall.sh [--purge]"; exit 1; }

APP=zhulong-pqm
PURGE="${1:-}"

echo "停止并禁用服务..."
systemctl stop "$APP" 2>/dev/null || true
systemctl disable "$APP" 2>/dev/null || true
rm -f /etc/systemd/system/$APP.service
systemctl daemon-reload

echo "移除程序与 nginx 配置..."
rm -rf /opt/$APP
rm -f /etc/nginx/conf.d/$APP.conf
nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true

if [ "$PURGE" = "--purge" ]; then
  echo "清除数据与配置（--purge）..."
  rm -rf /var/lib/$APP /etc/$APP
  userdel "$APP" 2>/dev/null || true
  echo "已彻底卸载。"
else
  echo "已卸载（保留 /var/lib/$APP 数据与 /etc/$APP 配置；如需清除请加 --purge）。"
fi
