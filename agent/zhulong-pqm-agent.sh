#!/usr/bin/env bash
# ============================================================
# 烛龙 PQM 主机 Agent（PoC / M3 主机内生面采集）
# ------------------------------------------------------------
# 在【目标主机本地】采集 Agentless 网络扫描够不着的密码学使用点，
# 通过平台现有 ingest 通道回报：
#   - 本机监听的 TLS 服务证书（含仅绑 127.0.0.1 / 被安全组挡在外的端口）
#   - 磁盘上的证书文件（/etc/ssl、nginx、/opt/*/etc/tls 等）
#   - SSH 主机密钥类型与位数（远程拿不到）
#   - 本机加密库版本（openssl，→ SBOM）
#
# 用法：
#   ZPQM_API=http://127.0.0.1:8099/api/v1 ZPQM_PASS=*** ./zhulong-pqm-agent.sh
# 依赖：bash、curl、openssl、python3、ss（iproute2）、ssh-keygen
# ============================================================
set -uo pipefail

API="${ZPQM_API:-http://127.0.0.1:8099/api/v1}"
ZUSER="${ZPQM_USER:-admin}"
ZPASS="${ZPQM_PASS:-admin@1234}"
HOST="$(hostname)"
ok=0

jstr() { python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1"; }

echo "== 烛龙 PQM 主机 Agent @ ${HOST} → ${API} =="
TOKEN=$(curl -s -m 10 -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ZUSER\",\"password\":\"$ZPASS\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
[ -n "$TOKEN" ] || { echo "登录失败，检查 ZPQM_API/账号"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"

push_pem() { # name  pemfile —— body 经临时文件 --data @file，避免大 PEM 触发 ARG_MAX
  local tmp; tmp=$(mktemp)
  python3 -c 'import json,sys;open(sys.argv[3],"w").write(json.dumps({"name":sys.argv[1],"pem":open(sys.argv[2]).read(),"exposure":"internal"}))' "$1" "$2" "$tmp"
  curl -s -m 15 -X POST "$API/assets/import/pem" -H "$AUTH" -H 'Content-Type: application/json' --data @"$tmp" >/dev/null \
    && { echo "  [证书] $1"; ok=$((ok+1)); }
  rm -f "$tmp"
}

echo "[1] 本机监听的 TLS 服务（含仅 127.0.0.1 / 被安全组挡在外，外部 Agentless 扫不到）"
# 用进程替换避免管道 while 子 shell，使 ok 计数在主 shell 累加。
while read -r port; do
  [ -z "$port" ] && continue
  cert=$(echo | timeout 4 openssl s_client -connect "127.0.0.1:$port" -servername "$HOST" 2>/dev/null | openssl x509 2>/dev/null)
  [ -n "$cert" ] || continue
  tmp=$(mktemp); printf '%s\n' "$cert" >"$tmp"
  push_pem "${HOST} 本地TLS服务 :${port}" "$tmp"; rm -f "$tmp"
done < <(ss -H -tln 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un)

echo "[2] 磁盘证书文件（跳过 CA 信任库等大 bundle）"
while read -r f; do
  openssl x509 -in "$f" -noout >/dev/null 2>&1 || continue            # 跳过纯私钥/非证书
  [ "$(grep -c 'BEGIN CERTIFICATE' "$f" 2>/dev/null)" -le 3 ] || continue  # 跳过 CA bundle
  push_pem "${HOST} $(basename "$f")" "$f"
done < <(for d in /etc/ssl/certs /etc/pki/tls/certs /etc/nginx /opt/*/etc/tls /opt/*/etc; do
    find "$d" -maxdepth 3 -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.cer' \) 2>/dev/null
  done | sort -u | head -15)

echo "[3] SSH 主机密钥（远程无法读取主机密钥类型/位数）"
for pub in /etc/ssh/ssh_host_*_key.pub; do
  [ -f "$pub" ] || continue
  line=$(ssh-keygen -l -f "$pub" 2>/dev/null) || continue
  bits=$(echo "$line" | awk '{print $1}')
  algo=$(echo "$line" | grep -oE '\((RSA|ECDSA|ED25519|DSA)\)' | tr -d '()')
  [ -n "$algo" ] || algo=RSA
  body=$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"system":sys.argv[2],"layer":"L2","algorithm":sys.argv[3],"keySize":int(sys.argv[4] or 0),"protocol":"SSH","exposure":"internal","source":"manual"}))' \
    "${HOST} SSH主机密钥 ${algo}" "$HOST" "$algo" "${bits:-0}")
  curl -s -m 10 -X POST "$API/assets" -H "$AUTH" -H 'Content-Type: application/json' --data "$body" >/dev/null \
    && { echo "  [SSH] ${algo}/${bits}"; ok=$((ok+1)); }
done

echo "[4] 本机加密库版本（→ CycloneDX SBOM）"
ov=$(openssl version 2>/dev/null | awk '{print $2}')
if [ -n "$ov" ]; then
  sbom=$(python3 -c 'import json,sys;print(json.dumps({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"openssl","version":sys.argv[1]}]}))' "$ov")
  curl -s -m 10 -X POST "$API/assets/import/sbom" -H "$AUTH" -H 'Content-Type: application/json' --data "$sbom" >/dev/null \
    && { echo "  [SBOM] openssl ${ov}"; ok=$((ok+1)); }
fi

echo "== 完成：本机共上报 ${ok} 个密码学使用点。到平台「密码使用点清单」查看（来源含 import/manual）=="
