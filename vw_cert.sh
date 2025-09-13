#!/usr/bin/env bash
# Vaultwarden 证书一键部署脚本
# 用法：把 PEM 和 KEY 内容粘进来，保存后执行一次即可

# ======== 1. 把证书内容粘到下面两行之间 ========
# 注意：保持缩进，头尾标记不要删，不要加多余空格或空行
read -r -d '' ORIGIN_PEM <<'EOF'
-----BEGIN CERTIFICATE-----
把你的完整 fullchain.cer / cert.pem 内容粘到这里
-----END CERTIFICATE-----
EOF

read -r -d '' ORIGIN_KEY <<'EOF'
-----BEGIN PRIVATE KEY-----
把你的 private.key 内容粘到这里
-----END PRIVATE KEY-----
EOF
# ======== 粘贴结束，下面别动 ========

set -euo pipefail

CERT_DIR="/srv/vaultwarden/certs"

# 1. 创建目录
sudo mkdir -p "$CERT_DIR"

# 2. 写入证书
echo "$ORIGIN_PEM" | sudo tee "$CERT_DIR/origin.pem" >/dev/null
echo "$ORIGIN_KEY" | sudo tee "$CERT_DIR/origin.key" >/dev/null

# 3. 一次给对权限
sudo chmod 640 "$CERT_DIR/origin.pem"
sudo chmod 600 "$CERT_DIR/origin.key"
sudo chown root:1000 "$CERT_DIR"/origin.*

# 4. 验证
echo "证书已写入，权限如下："
ls -l "$CERT_DIR"

echo "✅ 全部完成！"