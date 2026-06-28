#!/usr/bin/env bash
# 在目标机（Linux，需 root）安装烛龙 PQM：放置二进制与前端、生成配置、注册 systemd、配置 nginx、启动。
# 适配信创：自动按 uname -m 选 amd64 / arm64（鲲鹏/飞腾）。
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo ./install.sh"; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP=zhulong-pqm
PREFIX=/opt/$APP
DATA=/var/lib/$APP
ETC=/etc/$APP
SVCUSER=$APP

# 架构选择
m="$(uname -m)"
case "$m" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $m（仅 amd64/arm64）"; exit 1 ;;
esac
BIN="$HERE/bin/zhulong-pqm-linux-$ARCH"
[ -f "$BIN" ] || { echo "缺少二进制 $BIN（请确认交付包完整）"; exit 1; }
echo "目标架构：$m → $ARCH"

echo "[1/6] 创建系统用户与目录..."
id -u "$SVCUSER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVCUSER"
install -d -m 755 "$PREFIX/bin" "$PREFIX/web" "$ETC"
install -d -m 750 -o "$SVCUSER" -g "$SVCUSER" "$DATA"

echo "[2/6] 安装后端二进制与前端静态资源..."
install -m 755 "$BIN" "$PREFIX/bin/$APP"
rm -rf "${PREFIX:?}/web"/*
cp -r "$HERE/web/"* "$PREFIX/web/"

echo "[3/6] 写入运行配置（首次安装生成随机 JWT 密钥）..."
if [ ! -f "$ETC/$APP.env" ]; then
  SECRET="$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48)"
  sed "s#__JWT_SECRET__#${SECRET}#" "$HERE/config/$APP.env" > "$ETC/$APP.env"
  chmod 640 "$ETC/$APP.env"; chown root:"$SVCUSER" "$ETC/$APP.env"
  echo "      已生成随机 JWT 密钥 → $ETC/$APP.env"
else
  echo "      $ETC/$APP.env 已存在，保留不覆盖"
fi

echo "[4/6] 注册 systemd 服务..."
cp "$HERE/systemd/$APP.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$APP" >/dev/null 2>&1 || true

echo "[5/6] 配置 nginx（前端静态 + /api 反代）..."
if command -v nginx >/dev/null 2>&1 && [ -d /etc/nginx/conf.d ]; then
  cp "$HERE/nginx/$APP.conf" /etc/nginx/conf.d/
  if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
    echo "      nginx 已重载"
  else
    echo "      ⚠ nginx 配置校验未通过，请手工检查 /etc/nginx/conf.d/$APP.conf"
  fi
else
  echo "      ⚠ 未检测到 nginx 或 /etc/nginx/conf.d，已跳过；配置见 $HERE/nginx/$APP.conf"
fi

echo "[6/6] 启动服务..."
systemctl restart "$APP"
sleep 1

echo
if systemctl is-active --quiet "$APP"; then
  echo "✅ 安装完成，服务已运行"
else
  echo "⚠ 服务未处于 active，请查看：journalctl -u $APP -n 50"
fi
echo "   后端    : 127.0.0.1:8099（systemd 单元 $APP；0.0.0.0:8099 建议防火墙仅放行回环/nginx）"
echo "   前端    : 经 nginx 80 端口（站点根 $PREFIX/web）"
echo "   数据库  : $DATA/$APP.db"
echo "   配置    : $ETC/$APP.env"
echo "   默认账号: admin / admin@1234（首次登录后请立即改密）"
echo "   升级    : 覆盖安装即可（DB 与 env 不被覆盖）；卸载见 ./uninstall.sh"
