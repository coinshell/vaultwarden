#!/usr/bin/env bash
# Vaultwarden Installer – x86_64 / ARM64 自适应通用版
set -euo pipefail
umask 077

##########  必须填写  ##########
VW_DOMAIN=""
R2_BUCKET=""
R2_ENDPOINT=""
R2_ACCESS_KEY=""
R2_SECRET_KEY=""
##########  路径常量  ##########
STACK_DIR="/srv/vaultwarden"
DATA_DIR="$STACK_DIR/vw-data"
BACKUP_ENV="/etc/vaultwarden-backup.env"
SECRETS_FILE="$STACK_DIR/vaultwarden-secrets.json"
LOG_DIR="/var/log/vaultwarden"
LOCK_FILE="/var/run/vaultwarden-install.lock"
CRED_DIR="/dev/shm/vaultwarden"
RESTIC_PW_FILE="$CRED_DIR/restic.pw"
SIGNUPS_ALLOWED="true"

##########  日志  ##########
log_info(){ echo -e "\033[36m[INFO]\033[0m $*"; }
log_ok(){ echo -e "\033[32m[OK]\033[0m $*"; }
log_err(){ echo -e "\033[31m[ERROR]\033[0m $*" >&2; }

cmd_ok(){ command -v "$1" &>/dev/null; }
retry_cmd(){
  local n=0; local max=5
  until "$@"; do
    ((n++)) ; ((n>=max)) && { log_err "$* 连续失败"; exit 1; }
    sleep $((n*2))
  done
}

##########  自适应架构检测  ##########
get_arch(){
  local arch
  arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
  case "$arch" in
    amd64|arm64) echo "$arch" ;;
    *) log_err "不受支持的架构: $arch"; exit 1 ;;
  esac
}

ARCH=$(get_arch)
log_info "检测到的系统架构: $ARCH"

##########  通用 Docker 安装（自适应架构）  ##########
install_docker(){
  cmd_ok docker && docker compose version &>/dev/null && return 0
  export DEBIAN_FRONTEND=noninteractive
  local os_id=$(. /etc/os-release && echo "$ID")
  local os_ver=$(. /etc/os-release && echo "$VERSION_CODENAME")

  # --------- 截图 5 行开始 ---------
  apt-key del 7EA0A9C3F273FCD8 &>/dev/null || true
  rm -f /etc/apt/trusted.gpg.d/docker*.gpg
  rm -f /etc/apt/sources.list.d/docker.list
  # --------- 截图 5 行结束 ---------

  retry_cmd apt-get update -qq
  retry_cmd apt-get install -y ca-certificates curl gnupg lsb-release
  mkdir -p /etc/apt/keyrings
  retry_cmd curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /tmp/docker.gpg
  gpg --dearmor </tmp/docker.gpg >/etc/apt/keyrings/docker-archive-keyring.gpg
  chmod 644 /etc/apt/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] \
        https://download.docker.com/linux/${os_id} ${os_ver} stable" \
        > /etc/apt/sources.list.d/docker.list
  retry_cmd apt-get update -qq
  retry_cmd apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  while ! systemctl is-active --quiet docker; do sleep 2; done
  log_ok "Docker $ARCH 就绪（含截图 key 清理逻辑）"
}

##########  系统依赖  ##########
install_deps(){
  export DEBIAN_FRONTEND=noninteractive
  for pkg in curl jq sqlite3 rsync; do cmd_ok "$pkg" || apt-get install -y "$pkg"; done
  cmd_ok cron || apt-get install -y cron
  install_docker
}

##########  目录初始化  ##########
init_dirs(){
  mkdir -p "$DATA_DIR" "$STACK_DIR"/caddy-{data,config} "$LOG_DIR" "$CRED_DIR"
}

##########  生成密钥  ##########
gen_creds(){
  if [[ -f "$SECRETS_FILE" ]]; then
    log_info "复用已有密钥"
    RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
  else
    RESTIC_PASSWORD=$(openssl rand -base64 32)
    jq -n --arg r "$RESTIC_PASSWORD" '{RESTIC_PASSWORD:$r}' > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
  fi
  printf '%s' "$RESTIC_PASSWORD" > "$RESTIC_PW_FILE"
  chmod 600 "$RESTIC_PW_FILE"
  cat > "$BACKUP_ENV" <<EOF
R2_BUCKET="$R2_BUCKET"
R2_ENDPOINT="$R2_ENDPOINT"
R2_ACCESS_KEY="$R2_ACCESS_KEY"
R2_SECRET_KEY="$R2_SECRET_KEY"
RESTIC_PASSWORD_FILE="$RESTIC_PW_FILE"
DATA_DIR="$DATA_DIR"
STACK_DIR="$STACK_DIR"
EOF
  chmod 600 "$BACKUP_ENV"
}

##########  生成 Compose & Caddyfile  ##########
gen_compose(){
  cat > "$STACK_DIR/docker-compose.yml" <<EOF
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: https://${VW_DOMAIN}:443
      SIGNUPS_ALLOWED: ${SIGNUPS_ALLOWED}
      LOG_LEVEL: warn
    volumes:
      - ${DATA_DIR}:/data
    networks:
      - vw-network
  caddy:
    image: caddy:alpine
    container_name: caddy
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy-data:/data
      - ./caddy-config:/config
      - /srv/vaultwarden/certs:/certs:ro
    depends_on:
      - vaultwarden
    networks:
      - vw-network
networks:
  vw-network:
    driver: bridge
EOF
}

gen_caddyfile(){
  cat > "$STACK_DIR/Caddyfile" <<EOF
{
}
${VW_DOMAIN}:443 {
    tls /certs/origin.pem /certs/origin.key
    reverse_proxy /notifications/hub vaultwarden:3012
    reverse_proxy /notifications/hub/negotiate vaultwarden:80
    reverse_proxy vaultwarden:80 {
        header_up X-Real-IP {remote_host}
    }
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        -Server
    }
}
EOF
}

##########  备份脚本  ##########
install_backup_script(){
  cat > /usr/local/bin/vw-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /etc/vaultwarden-backup.env
IMAGE=restic/restic:0.17.3
COMMON="-e AWS_ACCESS_KEY_ID=$R2_ACCESS_KEY \
        -e AWS_SECRET_ACCESS_KEY=$R2_SECRET_KEY \
        -e RESTIC_PASSWORD_FILE=/run/secrets/restic.pw \
        -e RESTIC_REPOSITORY=s3:$R2_ENDPOINT/$R2_BUCKET \
        -v $RESTIC_PASSWORD_FILE:/run/secrets/restic.pw:ro \
        -v $DATA_DIR:/data:ro \
        -v $STACK_DIR/vaultwarden-secrets.json:/secrets.json:ro \
        --rm"
if ! docker run $COMMON "$IMAGE" snapshots &>/dev/null; then
  echo "首次初始化 restic 仓库..."
  docker run $COMMON "$IMAGE" init || { echo "仓库初始化失败"; exit 1; }
fi
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
sqlite3 "$DATA_DIR/db.sqlite3" ".backup '$TMP/db.sqlite3'"
rsync -a --exclude='*.tmp' --exclude='*.bak' "$DATA_DIR"/ "$TMP/"
cp "$STACK_DIR/vaultwarden-secrets.json" "$TMP/"
docker run $COMMON -v "$TMP:/mnt" "$IMAGE" backup /mnt
docker run $COMMON "$IMAGE" forget --prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --keep-yearly 3
echo "备份完成"
EOF
  chmod +x /usr/local/bin/vw-backup
}

##########  状态脚本  ##########
install_status_script(){
  cat > /usr/local/bin/vw-status <<'EOF'
#!/usr/bin/env bash
exec 200>/var/run/vaultwarden-status.lock
flock -n 200 || { echo "其他 status 正在执行"; exit 1; }
cd /srv/vaultwarden && docker compose ps
EOF
  chmod +x /usr/local/bin/vw-status
}

##########  每日体检脚本  ##########
install_health_script(){
  cat > /usr/local/bin/vw-health <<'EOF'
#!/usr/bin/env bash
exec 200>/var/run/vaultwarden-health.lock
flock -n 200 || { echo "其他 health 正在执行"; exit 1; }
LOG=/var/log/vaultwarden/health.log
{
  echo "=== $(date) ==="
  echo "--- Docker ---"
  systemctl is-active docker || { echo "Docker 未运行"; exit 1; }
  echo "--- Compose ---"
  cd /srv/vaultwarden
  docker compose ps
  echo "--- Users ---"
  sqlite3 vw-data/db.sqlite3 "SELECT email FROM users;" || echo "No users!"
  echo "--- Backup ---"
  /usr/local/bin/vw-backup >/dev/null && echo "Backup OK" || echo "Backup FAIL"
} >> "$LOG" 2>&1
EOF
  chmod +x /usr/local/bin/vw-health
  echo "0 6 * * * root /usr/local/bin/vw-health" >> /etc/cron.d/vaultwarden-health
}

##########  定时 & 日志轮转  ##########
setup_cron(){
  echo "0 3 * * * root /usr/local/bin/vw-backup >> $LOG_DIR/backup.log 2>&1" > /etc/cron.d/vaultwarden-backup
  echo "0 4 * * * root docker system prune -f >> $LOG_DIR/prune.log 2>&1" >> /etc/cron.d/vaultwarden-backup
  cat > /etc/logrotate.d/vaultwarden <<EOF
$LOG_DIR/*.log {
    daily rotate 7 compress delaycompress missingok notifempty
}
EOF
}

##########  启动栈  ##########
start_stack(){
  cd "$STACK_DIR"
  docker compose up -d
  until docker compose ps | grep -q "Up"; do
    log_info "等待服务启动..."
    sleep 2
  done
  log_ok "Vaultwarden ($ARCH) 已运行在 https://$VW_DOMAIN:443"
}

##########  主入口  ##########
main(){
  exec 200>"$LOCK_FILE"
  flock -n 200 || { log_err "已有实例在运行，退出"; exit 1; }

  log_info "开始安装 Vaultwarden ($ARCH)"
  install_deps
  init_dirs
  gen_creds
  gen_compose
  gen_caddyfile
  install_backup_script
  install_status_script
  install_health_script
  setup_cron
  start_stack

  log_ok "安装完成！常用命令："
  log_info "  手动备份  : sudo vw-backup"
  log_info "  查看状态  : sudo vw-status"
  log_info "  每日体检  : sudo vw-health"
  log_info "  密钥文件  : $SECRETS_FILE"
}

main "$@"