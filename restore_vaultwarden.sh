#!/usr/bin/env bash
# Vaultwarden Restore – x86_64 / ARM64 自适应通用版（2025-09-16 优化版）
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
BACKUP_ENV="/etc/vaultwarden-backup.env"
CRED_DIR="/srv/vaultwarden/certs"
SIGNUPS_ALLOWED="false"
RESTORE_LOG="$LOG_DIR/restore.log"

##########  镜像版本  ##########
VW_IMAGE="vaultwarden/server:1.33.0"
CADDY_IMAGE="caddy:2.10.0-alpine"
RESTIC_IMAGE="restic/restic:0.18.0"

##########  日志函数  ##########
mkdir -p "$LOG_DIR"
chown root:root "$LOG_DIR"
: > "$RESTORE_LOG"
log_info(){ echo -e "\033[36m[INFO]\033[0m $*" | tee -a "$RESTORE_LOG"; }
log_ok(){ echo -e "\033[32m[OK]\033[0m $*" | tee -a "$RESTORE_LOG"; }
log_err(){ echo -e "\033[31m[ERROR]\033[0m $*" | tee -a "$RESTORE_LOG" >&2; }
log_warn(){ echo -e "\033[33m[WARNING]\033[0m $*" | tee -a "$RESTORE_LOG" >&2; }

cmd_ok(){ command -v "$1" &>/dev/null; }
retry_cmd(){
  local n=0; local max=5
  until "$@"; do
    ((n++)); (( n>=max )) && { log_err "命令连续失败: $*"; exit 1; }
    log_info "命令失败，重试第 $n 次: $*"; sleep $((n*2))
  done
}

##########  系统检查  ##########
check_system(){
  [[ $EUID -eq 0 ]] || { log_err "请用 root 运行"; exit 1; }
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log_info "检测到系统: ${PRETTY_NAME:-$NAME}"
    case "$ID" in
      debian|ubuntu) ;;
      *) log_err "不支持的系统: $ID (仅支持 Debian/Ubuntu 系列)"; exit 1 ;;
    esac
  else
    log_err "/etc/os-release 不存在，无法判断系统"; exit 1
  fi
  local avail
  local path_for_df="${STACK_DIR:-/}"
  avail=$(df --output=avail "$path_for_df" 2>/dev/null | tail -n1 || echo 0)
  (( avail >= 524288 )) || { log_err "磁盘可用空间不足 (<512MB). 路径: $path_for_df 可用: ${avail}KB"; exit 1; }
  log_info "系统检查通过，磁盘可用 ${avail} KB"
}

##########  自适应架构  ##########
get_arch(){
  local arch
  arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
  case "$arch" in amd64|arm64) echo "$arch" ;; *) log_err "不受支持的架构: $arch"; exit 1 ;; esac
}

##########  环境检查  ##########
check_env(){
  if [[ -f "$SECRETS_FILE" ]]; then
    RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
    log_info "从 $SECRETS_FILE 读取 RESTIC_PASSWORD"
  else
    read -rsp "请输入 RESTIC_PASSWORD: " RESTIC_PASSWORD; echo
  fi
  local vars=(VW_DOMAIN R2_BUCKET R2_ENDPOINT R2_ACCESS_KEY R2_SECRET_KEY RESTIC_PASSWORD)
  for v in "${vars[@]}"; do
    [[ -n "${!v:-}" ]] || { log_err "请设置变量 $v（脚本顶部写死或环境提供）"; exit 1; }
  done
}

##########  验证/初始化 Restic 仓库  ##########
validate_restic_password(){
  log_info "验证 RESTIC_PASSWORD 和仓库访问权限..."
  local common_args=(
    -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY"
    -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY"
    -e RESTIC_PASSWORD="$RESTIC_PASSWORD"
    -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET"
  )
  
  # 尝试列出快照 - 如果成功，说明仓库已存在且密码正确
  local output
  if output=$(docker run --rm "${common_args[@]}" "$RESTIC_IMAGE" snapshots 2>&1); then
    log_info "Restic 仓库验证成功"
    return 0
  fi
  
  # 分析错误原因
  if echo "$output" | grep -qi "repository not found\|no such bucket\|does not exist"; then
    log_info "仓库不存在，正在初始化..."
    docker run --rm "${common_args[@]}" "$RESTIC_IMAGE" init || {
      log_err "Restic 仓库初始化失败"
      exit 1
    }
    log_ok "Restic 仓库初始化成功"
  elif echo "$output" | grep -qi "wrong password\|decrypt"; then
    log_err "RESTIC_PASSWORD 错误: $output"
    exit 1
  elif echo "$output" | grep -qi "access denied\|forbidden\|unauthorized"; then
    log_err "R2 凭据错误或权限不足: $output"
    exit 1
  elif echo "$output" | grep -qi "timeout\|connection refused\|network"; then
    log_err "网络连接问题: $output"
    exit 1
  else
    log_err "未知错误: $output"
    exit 1
  fi
}

##########  安装最新版 Docker CE ##########
install_docker(){
  local ARCH
  ARCH=$(get_arch)
  cmd_ok docker && docker compose version &>/dev/null && return 0

  export DEBIAN_FRONTEND=noninteractive
  local os_id=$( . /etc/os-release && echo "$ID" )
  local os_cod=$(. /etc/os-release; echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")

  for cmd in curl gpg; do
    cmd_ok "$cmd" || { apt-get update -qq && apt-get install -y "$cmd"; }
  done
  retry_cmd apt-get update -qq
  retry_cmd apt-get install -y ca-certificates gnupg lsb-release

  mkdir -p /etc/apt/keyrings
  local keyfile=/etc/apt/keyrings/docker-archive-keyring.gpg
  if [[ ! -f "$keyfile" ]]; then
    retry_cmd curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /tmp/docker.gpg
    gpg --dearmor </tmp/docker.gpg > "$keyfile"
    chmod 644 "$keyfile"
    rm -f /tmp/docker.gpg
  fi

  local listfile=/etc/apt/sources.list.d/docker.list
  echo "deb [arch=$ARCH signed-by=$keyfile] https://download.docker.com/linux/${os_id} ${os_cod} stable" > "$listfile"

  retry_cmd apt-get update -qq
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  systemctl enable --now docker
  while ! systemctl is-active --quiet docker; do sleep 2; done

  if docker run --rm hello-world >/dev/null 2>&1; then
    log_ok "Docker $(docker -v | awk '$1=="Docker"{print $3}' | tr -d ,) / Compose $(docker compose version --short) 安装成功"
  else
    log_err "Docker 安装后验证失败"; exit 1
  fi
}

##########  系统依赖  ##########
install_deps(){
  export DEBIAN_FRONTEND=noninteractive
  retry_cmd apt-get update -qq
  for pkg in curl jq sqlite3 rsync; do 
    cmd_ok "$pkg" || apt-get install -y "$pkg"
  done
  cmd_ok cron || apt-get install -y cron
  install_docker
}

##########  目录初始化  ##########
init_dirs(){
  mkdir -p "$DATA_DIR" "$STACK_DIR"/caddy-{data,config} "$LOG_DIR" "$CRED_DIR"
  chmod 700 "$CRED_DIR"
}

##########  获取最新快照  ##########
get_latest_snap(){
  log_info "获取最新的 restic 快照..."
  local common_args=(
    -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY"
    -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY"
    -e RESTIC_PASSWORD="$RESTIC_PASSWORD"
    -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET"
  )
  local all_snaps
  all_snaps=$(docker run --rm "${common_args[@]}" "$RESTIC_IMAGE" snapshots --json) || {
    log_err "获取快照列表失败"; exit 1
  }
  [[ -z "$all_snaps" || "$all_snaps" == "[]" ]] && { log_err "未找到可用的快照"; exit 1; }
  local latest_snap
  latest_snap=$(echo "$all_snaps" | jq -r 'sort_by(.time) | .[-1].id') || {
    log_err "解析快照列表失败"; exit 1
  }
  log_info "Running restic check (metadata level)..."
docker run --rm "${common_args[@]}" "$RESTIC_IMAGE" check >/dev/null || {
  log_err "Repository metadata check failed"; exit 1
}
  log_ok "Repository metadata check passed"

  log_info "Sampling 5 % of repo data blocks for corruption detection..."
  sample_output=$(docker run --rm "${common_args[@]}" "$RESTIC_IMAGE" \
                check --read-data-subset=5% 2>&1) || {
  log_err "Data block sampling found corruption:\n$sample_output"; exit 1
}
  log_ok "Data block sampling passed (5 % subset, no errors)"
  SNAP_ID="$latest_snap"
  log_ok "已选择最新有效快照: $SNAP_ID"
}

##########  执行还原  ##########
do_restore(){
  local restore_tmp
  restore_tmp="$(mktemp -d /tmp/vw-restore-XXXXXX)" || { log_err "mktemp 创建目录失败"; exit 1; }
  chmod 700 "$restore_tmp"
  trap "rm -rf '$restore_tmp'" EXIT
  
  log_ok "本次恢复所用快照 ID: $SNAP_ID"
  docker run --rm \
    -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
    -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
    -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
    -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
    -v "$restore_tmp":/restore \
    "$RESTIC_IMAGE" restore "$SNAP_ID" --target /restore || { log_err "restic restore 失败"; exit 1; }
  
  local DATA_SRC=""
  local candidates=()
  mapfile -t candidates < <(find "$restore_tmp" -type f -name 'db.sqlite3' -printf '%h\n' 2>/dev/null || true)
  if (( ${#candidates[@]} > 0 )); then
    DATA_SRC="${candidates[0]}"
    log_info "定位到 db.sqlite3，使用目录：$DATA_SRC"
  else
    mapfile -t candidates < <(find "$restore_tmp" -type d \( -name 'vw-data' -o -name 'attachments' -o -name 'vaultwarden' \) -print 2>/dev/null || true)
    if (( ${#candidates[@]} > 0 )); then
      DATA_SRC="${candidates[0]}"
      log_info "按常见目录名定位到：$DATA_SRC"
    else
      DATA_SRC="$restore_tmp"
      local depth=0 max_depth=6
      while (( depth < max_depth )); do
        local entries=( "$DATA_SRC"/* )
        if (( ${#entries[@]} == 1 && -d "${entries[0]}" )); then
          DATA_SRC="${entries[0]}"; ((depth++)); continue
        fi
        break
      done
      log_info "最终猜测的数据源目录为：$DATA_SRC"
    fi
  fi
  
  if [[ -f "$STACK_DIR/docker-compose.yml" ]]; then
    (cd "$STACK_DIR" && docker compose down) || true
  fi
  
  local rollback_dir="$STACK_DIR/rollback-$(date +%F-%H%M%S)"
  if [[ -d "$DATA_DIR" && "$(ls -A "$DATA_DIR" 2>/dev/null || true)" ]]; then
    mkdir -p "$rollback_dir"
    rsync -a --delete "$DATA_DIR"/ "$rollback_dir"/ || { log_err "备份现有数据失败"; exit 1; }
    log_info "现有数据已备份到: $rollback_dir"
  fi
  
  mkdir -p "$DATA_DIR"
  rm -rf "$DATA_DIR"/* || true
  if ! rsync -a "${DATA_SRC%/}/" "$DATA_DIR/"; then
    log_err "rsync 写入数据失败，开始回滚"
    [[ -d "$rollback_dir" ]] && { rm -rf "$DATA_DIR"/*; rsync -a "${rollback_dir%/}/" "$DATA_DIR/"; }
    sqlite3 "$DATA_DIR/db.sqlite3" "PRAGMA integrity_check;" | grep -q '^ok$' || {
      log_err "回滚后数据仍不完整，请手动检查！"; exit 1
    }
    log_info "回滚完成，数据正常；重新启动栈..."
    (cd "$STACK_DIR" && docker compose up -d) || true
    exit 1
  fi
  
  chown -R 1000:1000 "$DATA_DIR" || true
  [[ -f "$DATA_DIR/db.sqlite3" ]] && chmod 600 "$DATA_DIR/db.sqlite3"
  
  if [[ -f "$DATA_DIR/db.sqlite3" ]]; then
    if ! sqlite3 "$DATA_DIR/db.sqlite3" "PRAGMA integrity_check;" | grep -q '^ok$'; then
      log_err "数据库完整性校验失败，开始回滚"
      [[ -d "$rollback_dir" ]] && { rm -rf "$DATA_DIR"/*; rsync -a "${rollback_dir%/}/" "$DATA_DIR/"; log_info "已回滚"; }
      (cd "$STACK_DIR" && docker compose up -d) || true
      exit 1
    fi
    log_ok "数据库完整性检查通过"
  else
    log_err "恢复后未找到 db.sqlite3，开始回滚"
    [[ -d "$rollback_dir" ]] && { rm -rf "$DATA_DIR"/*; rsync -a "${rollback_dir%/}/" "$DATA_DIR/"; log_info "已回滚"; }
    (cd "$STACK_DIR" && docker compose up -d) || true
    exit 1
  fi
  log_ok "数据恢复完成"
}

##########  生成 Compose & Caddyfile  ##########
gen_compose(){
  case "${SIGNUPS_ALLOWED,,}" in true|1|yes) SIGNUPS_ALLOWED=true ;; *) SIGNUPS_ALLOWED=false ;; esac
  cat > "$STACK_DIR/docker-compose.yml" <<EOF
services:
  vaultwarden:
    image: $VW_IMAGE
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: https://${VW_DOMAIN}
      SIGNUPS_ALLOWED: ${SIGNUPS_ALLOWED}
      LOG_LEVEL: warn
    volumes:
      - ${DATA_DIR}:/data
    networks:
      - vw-network
  caddy:
    image: $CADDY_IMAGE
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
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
  log_info "生成 docker-compose.yml"
}

gen_caddyfile(){
  cat > "$STACK_DIR/Caddyfile" <<EOF
http:// {
    redir https://{host}{uri} permanent
}
${VW_DOMAIN}:443 {
    tls /certs/origin.pem /certs/origin.key
    reverse_proxy /notifications/hub vaultwarden:80
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
  log_info "生成 Caddyfile（已含 80→443 跳转）"
}

##########  安装备份脚本  ##########
install_backup_script() {
  cat > /usr/local/bin/vw-backup << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077

# 配置常量
LOG_FILE="/var/log/vaultwarden/backup.log"
LOCK_FILE="/var/run/vaultwarden-backup.lock"
BACKUP_ENV="/etc/vaultwarden-backup.env"
DATA_DIR="/srv/vaultwarden/vw-data"
STACK_DIR="/srv/vaultwarden"
RESTIC_IMAGE="restic/restic:0.18.0"

# 检查环境配置文件
[[ -f "$BACKUP_ENV" ]] || {
  echo "❌ 备份环境文件 $BACKUP_ENV 不存在" | tee -a "$LOG_FILE"
  exit 1
}

# 加载环境变量
# shellcheck source=/dev/null
source "$BACKUP_ENV"

# 检查密钥文件
[[ -f "$SECRETS_FILE" ]] || {
  echo "❌ SECRETS_FILE $SECRETS_FILE 不存在" | tee -a "$LOG_FILE"
  exit 1
}

# 获取 restic 密码
RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")

# 设置文件锁
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "【跳过】另一个备份实例正在运行" | tee -a "$LOG_FILE"
  exit 0
fi

# 日志函数
log() {
  echo "$(date '+%F %T') - $*" | tee -a "$LOG_FILE"
}

log_err() {
  echo "$(date '+%F %T') - ERROR: $*" | tee -a "$LOG_FILE" >&2
}

log "=== 开始备份 ==="

# 检查数据目录
[[ -d "$DATA_DIR" ]] || {
  log_err "数据目录 $DATA_DIR 不存在"
  exit 1
}

# 执行备份
log "执行备份操作..."
docker run --rm \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  -v "$DATA_DIR":/data:ro \
  "$RESTIC_IMAGE" backup /data --json 2>/tmp/restic-warn.log >/tmp/restic-summary.json

# 检查备份结果
if [ $? -ne 0 ]; then
  log_err "备份失败: $(cat /tmp/restic-warn.log)"
  exit 1
fi

# 提取快照 ID
SNAP_ID=$(jq -r 'select(.message_type=="summary").snapshot_id' /tmp/restic-summary.json)
rm -f /tmp/restic-warn.log /tmp/restic-summary.json

[[ -z "$SNAP_ID" || "$SNAP_ID" == "null" ]] && {
  log_err "无法提取快照 ID"
  exit 1
}

log "成功创建快照: $SNAP_ID"

# 验证备份完整性
log "运行 restic 检查（元数据级别）..."
docker run --rm \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  "$RESTIC_IMAGE" check >/dev/null || {
  log_err "存储库元数据检查失败"
  exit 1
}

log "✅ 存储库元数据检查通过"

log "抽样 5% 的存储库数据块进行损坏检测..."
docker run --rm \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  "$RESTIC_IMAGE" check --read-data-subset=5% || {
  log_err "数据块抽样发现损坏"
  exit 1
}

log "✅ 数据块抽样通过（5% 子集，无错误）"

# 清理旧备份
log "清理旧备份（保留最近7天）..."
docker run --rm \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  "$RESTIC_IMAGE" forget --keep-daily 7 --prune >/dev/null 2>&1 || log "⚠️ 清理旧备份失败"

log "=== 备份完成 ==="
EOF

  chmod +x /usr/local/bin/vw-backup
  log_info "备份脚本已安装：/usr/local/bin/vw-backup"
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
  log_info "状态脚本已安装：/usr/local/bin/vw-status"
}

##########  定时任务设置  ##########
setup_cron(){
  echo "0 3 * * * root /usr/local/bin/vw-backup >> $LOG_DIR/backup.log 2>&1" > /etc/cron.d/vaultwarden-backup
  echo "0 4 * * * root docker system prune -f --filter 'label!=vaultwarden' >> $LOG_DIR/prune.log 2>&1" >> /etc/cron.d/vaultwarden-backup
  log_info "配置定时备份和清理任务"
}

##########  每日体检脚本  ##########
install_health_script(){
  cat > /usr/local/bin/vw-health <<'EOF'
#!/bin/bash
set -e
LOCK_FILE=/var/run/vaultwarden-health.lock
LOG_FILE=/var/log/vaultwarden/health.log
BACKUP_ENV=/etc/vaultwarden-backup.env
DATA_DIR=/srv/vaultwarden/vw-data
STACK_DIR=/srv/vaultwarden
RESTIC_IMAGE=restic/restic:0.18.0

mkdir -p "$(dirname "$LOG_FILE")"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "【跳过】另一个健康检查实例正在运行"
  exit 0
fi

log(){
  echo "$(date '+%F %T') - $*" | tee -a "$LOG_FILE"
}
log_error_and_exit(){
  log "❌ $*"
  exit 1
}

{
  log "=== 开始体检 ==="

  log "检查 Docker..."
  systemctl is-active docker >/dev/null || log_error_and_exit "Docker 未运行"
  log "✅ Docker 正常"

  log "检查 Compose 栈..."
  [ -d "$STACK_DIR" ] || log_error_and_exit "$STACK_DIR 不存在"
  cd "$STACK_DIR"
# 把每行 JSON 先放进数组，再逐个判断 State
if docker compose ps --format json \
 | jq -r 'if type == "array" then .[].State else . end' \
 | grep -E 'exited|dead' | grep -q .; then
    log "⚠️  有容器异常退出，最近 20 行日志："
    docker compose logs --tail 20 | tee -a "$LOG_FILE"
    log_error_and_exit "有容器异常退出"
  fi
  log "✅ Compose 栈正常"

  log "检查用户数据库..."
  if [ -f "$DATA_DIR/db.sqlite3" ]; then
    users=$(sqlite3 "$DATA_DIR/db.sqlite3" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "未知")
    log "注册用户数: $users"
    log "✅ 数据库文件存在"
  else
    log "❌ 数据库文件不存在"
  fi

  log "检查备份配置..."
  if [ -f "$BACKUP_ENV" ]; then
    # shellcheck source=/dev/null
    source "$BACKUP_ENV"
    RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
    if [ -x /usr/local/bin/vw-backup ]; then
      bash -n /usr/local/bin/vw-backup || log_error_and_exit "备份脚本语法错误"
      log "✅ 备份脚本语法正确"
      
      output=$(docker run --rm \
  -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
  -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
  -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
  "$RESTIC_IMAGE" snapshots --last 10 2>&1) && rc=0 || rc=1
      
      if [ $rc -eq 0 ]; then
        log "✅ Restic 仓库已初始化"
      else
        if echo "$output" | grep -qi "no snapshot\|not found"; then
          log "✅ Restic 仓库已初始化（暂无快照）"
        else
          log "⚠️  Restic 仓库检查失败: $output"
        fi
      fi
    else
      log "❌ vw-backup 未安装或不可执行"
    fi
  else
    log "❌ 备份配置文件不存在: $BACKUP_ENV"
  fi

  log "=== 体检结束 ==="
} 2>&1 | tee -a "$LOG_FILE"
EOF
  chmod +x /usr/local/bin/vw-health
  log_info "每日体检脚本已安装：/usr/local/bin/vw-health"
}

##########  日志轮转  ##########
setup_logrotate(){
  cat > /etc/logrotate.d/vaultwarden <<EOF
$LOG_DIR/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
    if command -v systemctl &> /dev/null; then
         systemctl reload rsyslog.service > /dev/null 2>&1 || true
    else
        service rsyslog reload > /dev/null 2>&1 || true
    fi
    endscript
}
EOF
  log_info "配置日志轮转"
}

##########  启动栈 & 自启  ##########
start_stack(){
  chown -R root:root "$STACK_DIR"
  chmod 600 "$SECRETS_FILE"
  chmod 644 "$STACK_DIR"/docker-compose.yml \
            "$STACK_DIR"/Caddyfile 2>/dev/null || true
  cd "$STACK_DIR"
  docker compose up -d
  sleep 5
  if docker compose ps --format json | jq -r 'if type=="array" then .[].State else .State end' | grep -E 'exited|dead' | grep -q .; then
    log_err "检测到有已退出的容器（Exited），请检查容器日志：docker compose ps && docker compose logs"
    docker compose ps | tee -a "$RESTORE_LOG"
    docker compose logs --tail 50 | tee -a "$RESTORE_LOG"
    exit 1
  fi
  local tries=0
  until docker compose ps | grep -q "Up"; do
    sleep 2; ((tries++)); (( tries > 30 )) && { log_err "服务未能在超时时间内启动"; docker compose ps | tee -a "$RESTORE_LOG"; exit 1; }
    log_info "等待服务启动..."
  done
  log_ok "Vaultwarden ($ARCH) 已恢复并运行在 https://$VW_DOMAIN"
}

##########  HTTP 健康检查  ##########
wait_vw_http(){
  log_info "等待 Vaultwarden HTTP 服务响应..."
  local tries=0 max=30
  until curl -k -s -f "https://${VW_DOMAIN}/api/health" >/dev/null 2>&1 || \
        curl -k -s -f "https://${VW_DOMAIN}/" >/dev/null 2>&1; do
    sleep 3; ((tries++)); ((tries>max)) && { log_err "服务未在 $max 次检查后响应 /api/health 或 /"; exit 1; }
  done
  log_ok "Vaultwarden HTTP 服务已就绪"
}

##########  开机自启  ##########
enable_autostart(){
  if ! command -v systemctl &> /dev/null; then
    log_warn "systemctl 未找到，无法启用开机自启"
    return 0
  fi
  cat > /etc/systemd/system/vaultwarden.service <<EOF
[Unit]
Description=Vaultwarden Service
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=$(command -v docker) compose -f $STACK_DIR/docker-compose.yml up -d
ExecStop=$(command -v docker) compose -f $STACK_DIR/docker-compose.yml down
RemainAfterExit=yes
WorkingDirectory=$STACK_DIR
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable vaultwarden
  log_ok "Vaultwarden 已添加 systemd 开机自启 (vaultwarden.service)"
}

##########  主入口  ##########
main(){
  [[ -f "$LOCK_FILE" ]] && find "$LOCK_FILE" -mmin +10 -delete 2>/dev/null || true
  exec 200>"$LOCK_FILE"
  if ! flock -n 200; then
    log_err "已有另一个 Vaultwarden 恢复脚本正在运行，请稍后再试。"
    exit 1
  fi
  log_info "已获得脚本执行锁"
  
  check_system
  ARCH=$(get_arch)
  
  log_info "开始恢复 Vaultwarden ($ARCH)"
  install_deps
  check_env
  validate_restic_password
  init_dirs
  get_latest_snap
  do_restore

  # 持久化 RESTIC_PASSWORD
  if [[ ! -f "$SECRETS_FILE" ]]; then
    log_info "重建 $SECRETS_FILE"
    jq -n --arg r "$RESTIC_PASSWORD" '{RESTIC_PASSWORD:$r}' > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
  fi
  
  # 写入备份环境文件
  cat > "$BACKUP_ENV" <<EOF
R2_BUCKET="$R2_BUCKET"
R2_ENDPOINT="$R2_ENDPOINT"
R2_ACCESS_KEY="$R2_ACCESS_KEY"
R2_SECRET_KEY="$R2_SECRET_KEY"
DATA_DIR="$DATA_DIR"
STACK_DIR="$STACK_DIR"
RESTIC_IMAGE="$RESTIC_IMAGE"
SECRETS_FILE="$SECRETS_FILE"
EOF
  chmod 600 "$BACKUP_ENV"
  log_info "写入备份环境文件: $BACKUP_ENV"

  gen_compose
  gen_caddyfile
  install_backup_script
  install_status_script
  install_health_script
  setup_logrotate
  setup_cron
  start_stack
  wait_vw_http
  enable_autostart
  
  # 验证备份脚本可用性
  log_info "验证备份脚本可用性..."
  if /usr/local/bin/vw-backup >/dev/null 2>&1; then
    log_ok "备份验证通过"
  else
    log_warn "备份验证失败，请检查配置"
  fi

  # 清理 7 天前旧回滚目录
  find "$STACK_DIR" -maxdepth 1 -type d -name 'rollback-*' -mtime +7 -exec rm -rf {} + 2>/dev/null || true
  
  log_ok "恢复完成！常用命令："
  log_info "  手动备份  : sudo vw-backup"
  log_info "  查看状态  : sudo vw-status"
  log_info "  每日体检  : sudo vw-health"
  log_info "  访问地址  : https://$VW_DOMAIN"
  log_info "  密钥文件  : $SECRETS_FILE"
  log_info "  恢复日志  : $RESTORE_LOG"
}

main "$@"