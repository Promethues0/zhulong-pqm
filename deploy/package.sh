#!/usr/bin/env bash
# 把 deploy/dist/ 打成可交付的 tar.gz（跨平台，不依赖 GNU tar 扩展）。
# 用法：VERSION=1.0.0 ./package.sh   （不传 VERSION 时用当日日期）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$HERE/dist"
VERSION="${VERSION:-$(date +%Y%m%d)}"

[ -d "$STAGE" ] || { echo "未找到 dist/，请先运行 ./build.sh"; exit 1; }

PKG="zhulong-pqm-${VERSION}"
TMP="$HERE/$PKG"
OUT="$HERE/${PKG}.tar.gz"

rm -rf "$TMP" "$OUT"
cp -r "$STAGE" "$TMP"
tar -czf "$OUT" -C "$HERE" "$PKG"
rm -rf "$TMP"

echo "✅ 打包完成 → $OUT"
echo
echo "交付到目标机后："
echo "  tar xzf ${PKG}.tar.gz"
echo "  cd ${PKG}"
echo "  sudo ./install.sh"
