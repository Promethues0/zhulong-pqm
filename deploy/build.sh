#!/usr/bin/env bash
# 在开发机（macOS/Linux，需 go 1.23 + node）构建烛龙 PQM 私有化交付物：
#   - 后端：linux amd64 + arm64（信创 鲲鹏/飞腾）静态二进制，CGO 关闭（纯 Go SQLite）
#   - 前端：vite 生产构建 → web/
# 产物落在 deploy/dist/，随后用 package.sh 打成 tar.gz。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STAGE="$HERE/dist"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/web"

echo "[1/3] 构建后端（linux amd64 + arm64，CGO_ENABLED=0）..."
cd "$ROOT/backend"
for arch in amd64 arm64; do
  echo "      → linux/$arch"
  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" \
    -o "$STAGE/bin/zhulong-pqm-linux-$arch" ./cmd/zhulong-pqm
done

echo "[2/3] 构建前端（vite 生产构建）..."
cd "$ROOT/frontend"
[ -d node_modules ] || npm ci
npm run build
cp -r dist/* "$STAGE/web/"

echo "[3/3] 复制安装脚本与配置..."
cp "$HERE/install.sh" "$HERE/uninstall.sh" "$STAGE/"
cp -r "$HERE/systemd" "$HERE/nginx" "$HERE/config" "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/uninstall.sh"

echo
echo "✅ 构建完成 → $STAGE"
echo "   后端二进制：$(ls -1 "$STAGE"/bin/ | tr '\n' ' ')"
echo "   前端静态：$(find "$STAGE/web" -type f | wc -l | tr -d ' ') 个文件"
echo "   下一步：./package.sh 打包交付"
