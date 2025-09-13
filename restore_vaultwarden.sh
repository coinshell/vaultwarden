#!/usr/bin/env bash
# Vaultwarden Restore – x86_64 / ARM64 自适应通用版
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
SECRETS_FILE="$STACK_DIR/vaultwarden-secrets.json"
LOG_DIR="/var/log/vaultwarden"
LOCK_FILE="/var/run/vaultwarden-restore.lock"
CRED_DIR="/dev/shm/vaultwarden"
RESTIC_PW_FILE="$CRED_DIR/restic.pw"
BACKUP_ENV="/etc/vaultwarden-backup.env"
SIGNUPS_ALLOWED="false"

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

##########  检查环境  ##########
check_env(){
  [[ $EUID -eq 0 ]] || { log_err "请用 root 运行"; exit 1; }
  if [[ -f "$RESTIC_PW_FILE" ]]; then
    RESTIC_PASSWORD=$(<"$RESTIC_PW_FILE")
  elif [[ -f "$SECRETS_FILE" ]]; then
    RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
  else
    read -rsp "请输入 RESTIC_PASSWORD: " RESTIC_PASSWORD
    echo
  fi
  for v in VW_DOMAIN R2_BUCKET R2_ENDPOINT R2_ACCESS_KEY R2_SECRET_KEY RESTIC_PASSWORD; do
    [[ -n "${!v:-}" ]] || { log_err "请设置 $v"; exit 1; }
  done
}

##########  自适应 Docker 安装  ##########
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

##########  获取最新快照  ##########
get_latest_snap(){
  local json=$(docker run --rm \
    -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
    -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
    -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
    -e RESTIC_REPOSITORY=s3:"$R2_ENDPOINT/$R2_BUCKET" \
    restic/restic:0.17.3 snapshots --latest 1 --json)
  SNAP_ID=$(echo "$json" | jq -r '.[0].short_id')
  [[ "$SNAP_ID" == "null" || -z "$SNAP_ID" ]] && { log_err "获取快照失败"; exit 1; }
  log_info "最新快照 ID：$SNAP_ID"
}

##########  执行还原  ##########
do_restore(){
  # === 0. 创建临时目录 ===
  local restore_tmp
  restore_tmp="$(mktemp -d /tmp/vw-restore-XXXXXX)" || { log_err "mktemp 创建目录失败"; return 1; }
  chmod 700 "$restore_tmp"
  log_info "恢复临时目录: $restore_tmp"
  trap "rm -rf '$restore_tmp'" EXIT

  # === 1. Restic 还原 ===
  log_info "使用 restic restore 恢复快照到临时目录 ..."
  docker run --rm \
    -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
    -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
    -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
    -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
    -v "$restore_tmp":/restore \
    restic/restic:0.17.3 restore "$SNAP_ID" --target /restore \
    || { log_err "restic restore 失败"; return 1; }

  # === 2. 智能查找数据根目录 ===
  log_info "在恢复结果中查找 Vaultwarden 数据根..."
  local candidates=()
  mapfile -t candidates < <(
    find "$restore_tmp" -type f -name 'db.sqlite3' -printf '%h\n' 2>/dev/null || true
  )

  if (( ${#candidates[@]} > 0 )); then
    DATA_SRC="${candidates[0]}"
    log_info "定位到 db.sqlite3，使用目录：$DATA_SRC"
  else
    mapfile -t candidates < <(
      find "$restore_tmp" -type d \( -name 'vw-data' -o -name 'attachments' -o -name 'vaultwarden' \) -print 2>/dev/null || true
    )
    if (( ${#candidates[@]} > 0 )); then
      DATA_SRC="${candidates[0]}"
      log_info "按常见目录名定位到：$DATA_SRC"
    else
      # 兜底：逐层拍平单子目录（防止套娃）
      DATA_SRC="$restore_tmp"
      local depth=0 max_depth=6
      while (( depth < max_depth )); do
        local entries=( "$DATA_SRC"/* )
        if (( ${#entries[@]} == 1 && -d "${entries[0]}" )); then
          DATA_SRC="${entries[0]}"
          ((depth++))
          continue
        fi
        break
      done
      log_info "最终猜测的数据源目录为：$DATA_SRC"
    fi
  fi

  # === 3. 停止旧容器并备份现有数据 ===
  if [[ -f "$STACK_DIR/docker-compose.yml" ]]; then
    (cd "$STACK_DIR" && docker compose down) || true
  fi
  local rollback_dir="$STACK_DIR/rollback-$(date +%F-%H%M%S)"
  if [[ -d "$DATA_DIR" && "$(ls -A "$DATA_DIR" 2>/dev/null || true)" ]]; then
    mkdir -p "$rollback_dir"
    rsync -a --delete "$DATA_DIR"/ "$rollback_dir"/
    log_info "现有数据已备份到: $rollback_dir"
  fi

  # === 4. 写入新数据 ===
  mkdir -p "$DATA_DIR"
  rm -rf "$DATA_DIR"/*
  rsync -a "${DATA_SRC%/}/" "$DATA_DIR/"

  # === 5. 权限修复 ===
  chown -R 1000:1000 "$DATA_DIR" || true
  [[ -f "$DATA_DIR/db.sqlite3" ]] && chmod 600 "$DATA_DIR/db.sqlite3"

  # === 6. 数据完整性检查 ===
  if [[ -f "$DATA_DIR/db.sqlite3" ]]; then
    if sqlite3 "$DATA_DIR/db.sqlite3" "PRAGMA integrity_check;" | grep -q ok; then
      log_ok "数据库完整性检查通过"
    else
      log_err "数据库完整性校验失败，回滚目录在 $rollback_dir"
      return 1
    fi
  fi

  log_ok "数据恢复完成"
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

##########  管理脚本  ##########
install_scripts(){
  cat > /usr/local/bin/vw-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /etc/vaultwarden-backup.env
IMAGE=restic/restic:0.17.3
COMMON=( \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD_FILE=/run/secrets/restic.pw \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  -v "$RESTIC_PASSWORD_FILE":/run/secrets/restic.pw:ro \
  -v "$DATA_DIR":/data:ro \
  -v "$STACK_DIR/vaultwarden-secrets.json":/secrets.json:ro \
  --rm \
)
if ! docker run "${COMMON[@]}" "$IMAGE" snapshots --latest 1 >/dev/null; then
  echo "首次初始化 restic 仓库..."
  docker run "${COMMON[@]}" "$IMAGE" init || { echo "仓库初始化失败"; exit 1; }
fi
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
sqlite3 "$DATA_DIR/db.sqlite3" ".backup '$TMP/db.sqlite3'"
rsync -a --exclude='*.tmp' --exclude='*.bak' "$DATA_DIR"/ "$TMP/"
cp "$STACK_DIR/vaultwarden-secrets.json" "$TMP/"
docker run "${COMMON[@]}" -v "$TMP:/mnt" "$IMAGE" backup /mnt
docker run "${COMMON[@]}" "$IMAGE" forget --prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --keep-yearly 3
echo "备份成功"
EOF
  chmod +x /usr/local/bin/vw-backup

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
mkdir -p "$(dirname "$LOG")"

# 同时打印到终端并写日志
{
  echo "=== $(date) ==="
  echo "--- Docker ---"
  systemctl is-active docker || { echo "Docker 未运行"; exit 1; }
  echo "--- Compose ---"
  cd /srv/vaultwarden
  docker compose ps
  echo "--- Users ---"
  sqlite3 /srv/vaultwarden/vw-data/db.sqlite3 "SELECT email FROM users;" 2>/dev/null || echo "No users or DB not ready!"
  echo "--- Backup ---"
  /usr/local/bin/vw-backup >/dev/null && echo "Backup OK" || echo "Backup FAIL"
} 2>&1 | tee -a "$LOG"
EOF
  chmod +x /usr/local/bin/vw-health

  # 防止重复写入 crontab
  grep -q vaultwarden-health /etc/cron.d/vaultwarden-health 2>/dev/null || \
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
  log_ok "Vaultwarden ($ARCH) 已恢复并运行在 https://$VW_DOMAIN:443"
}

##########  主入口  ##########
main(){
  exec 200>"$LOCK_FILE"
  flock -n 200 || { log_err "已有实例在运行，退出"; exit 1; }

  log_info "开始恢复 Vaultwarden ($ARCH)"
  check_env
  install_deps
  init_dirs
  get_latest_snap
  do_restore

  # 重建 secrets 文件
  if [[ ! -f "$SECRETS_FILE" ]]; then
    log_info "重建 $SECRETS_FILE"
    jq -n --arg r "$RESTIC_PASSWORD" '{RESTIC_PASSWORD:$r}' > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
  fi

  # 定义 RESTIC_PASSWORD_FILE 变量
  local RESTIC_PASSWORD_FILE="$RESTIC_PW_FILE"
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

  gen_compose
  gen_caddyfile
  install_scripts
  install_health_script
  setup_cron
  start_stack

  log_ok "恢复完成！常用命令："
  log_info "  手动备份  : sudo vw-backup"
  log_info "  查看状态  : sudo vw-status"
  log_info "  每日体检  : sudo vw-health"
  log_info "  密钥文件  : $SECRETS_FILE"
}

main "$@"