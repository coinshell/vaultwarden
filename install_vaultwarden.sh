#!/usr/bin/env bash
# Vaultwarden Installer – x86_64 / ARM64 自适应通用版（实机可用版 2025-09-14）
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
CRED_DIR="/srv/vaultwarden/certs"
SIGNUPS_ALLOWED="true"
INSTALL_LOG="$LOG_DIR/install.log"

##########  镜像版本变量化 ##########
VW_IMAGE="vaultwarden/server:1.33.0"
CADDY_IMAGE="caddy:2.10.0-alpine"
RESTIC_IMAGE="restic/restic:0.18.0"

##########  日志  ##########
mkdir -p "$LOG_DIR"
: > "$INSTALL_LOG"
log_info(){ echo -e "\033[36m[INFO]\033[0m $*" | tee -a "$INSTALL_LOG"; }
log_ok(){ echo -e "\033[32m[OK]\033[0m $*" | tee -a "$INSTALL_LOG"; }
log_err(){ echo -e "\033[31m[ERROR]\033[0m $*" | tee -a "$INSTALL_LOG" >&2; }
log_warn(){ echo -e "\033[33m[WARNING]\033[0m $*" | tee -a "$INSTALL_LOG" >&2; }

cmd_ok(){ command -v "$1" &>/dev/null; }
retry_cmd(){
  local n=0; local max=5
  until "$@"; do
    ((n++))
    if (( n>=max )); then
      log_err "命令连续失败: $*"
      exit 1
    fi
    log_info "命令失败，重试第 $n 次: $*"
    sleep $((n*2))
  done
}

##########  系统检查 ##########
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

##########  必填变量检查  ##########
check_vars(){
  local vars=(VW_DOMAIN R2_BUCKET R2_ENDPOINT R2_ACCESS_KEY R2_SECRET_KEY)
  for v in "${vars[@]}"; do
    [[ -n "${!v:-}" ]] || { log_err "请设置变量 $v（脚本顶部写死或导出环境变量）"; exit 1; }
  done
}

##########  自适应架构检测  ##########
get_arch(){
  local arch
  arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
  case "$arch" in amd64|arm64) echo "$arch" ;; *) log_err "不受支持的架构: $arch"; exit 1 ;; esac
}

##########  安装最新版 Docker CE ##########
install_docker(){
  local ARCH
  ARCH=$(get_arch)
  # 已安装且 compose 可用则直接返回
  cmd_ok docker && docker compose version &>/dev/null && return 0

  export DEBIAN_FRONTEND=noninteractive
  local os_id=$( . /etc/os-release && echo "$ID" )
  local os_cod=$(. /etc/os-release; echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")

  # 安装基础工具（如已装会自动跳过）
  for cmd in curl gpg; do
    cmd_ok "$cmd" || { apt-get update -qq && apt-get install -y "$cmd"; }
  done
  retry_cmd apt-get update -qq
  retry_cmd apt-get install -y ca-certificates gnupg lsb-release

  # 确保 keyrings 目录存在
  mkdir -p /etc/apt/keyrings

  # 下载并固定密钥（如已存在则跳过下载，实现幂等）
  local keyfile=/etc/apt/keyrings/docker-archive-keyring.gpg
  if [[ ! -f "$keyfile" ]]; then
    retry_cmd curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /tmp/docker.gpg
    gpg --dearmor </tmp/docker.gpg > "$keyfile"
    chmod 644 "$keyfile"
    rm -f /tmp/docker.gpg
  fi

  # 写入源列表（如已存在则覆盖，保持幂等）
  local listfile=/etc/apt/sources.list.d/docker.list
  echo "deb [arch=$ARCH signed-by=$keyfile] https://download.docker.com/linux/${os_id} ${os_cod} stable" > "$listfile"

  # 安装/升级 Docker 与 Compose 插件
  retry_cmd apt-get update -qq
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # 启动并等待就绪
  systemctl enable --now docker
  while ! systemctl is-active --quiet docker; do sleep 2; done

  # 验证
  if docker run --rm hello-world >/dev/null 2>&1; then
    log_ok "Docker $(docker -v | awk '$1=="Docker"{print $3}' | tr -d ,) / Compose $(docker compose version --short) 安装成功"
  else
    log_err "Docker 安装后验证失败"; exit 1
  fi
}

##########  系统依赖  ##########
install_deps(){
  export DEBIAN_FRONTEND=noninteractive
  # 先更新包列表
  retry_cmd apt-get update -qq
  for pkg in curl jq sqlite3 rsync; do 
    cmd_ok "$pkg" || apt-get install -y "$pkg"
  done
  cmd_ok cron || apt-get install -y cron
  install_docker
}

##########  目录初始化  ##########
init_dirs(){
  mkdir -p "$DATA_DIR" "$STACK_DIR"/caddy-{data,config} "$LOG_DIR" "$CRED_DIR" /srv/vaultwarden/certs
  chmod 700 "$CRED_DIR"
}

##########  生成密钥 & 备份环境变量  ##########
gen_creds(){
  if [[ -f "$SECRETS_FILE" ]]; then
    log_info "复用已有密钥"
    RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
    [[ -n "$RESTIC_PASSWORD" ]] || { 
      log_err "从 $SECRETS_FILE 读取的 RESTIC_PASSWORD 为空" 
      exit 1 
    }
  else
    RESTIC_PASSWORD=$(openssl rand -base64 32)
    jq -n --arg r "$RESTIC_PASSWORD" '{RESTIC_PASSWORD:$r}' > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
  fi

  # 不再写入 RESTIC_PASSWORD_FILE 到备份环境文件
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
  log_info "备份环境文件已生成：$BACKUP_ENV"
}

##########  生成 Compose & Caddyfile  ##########
gen_compose(){
  SIGNUPS_ALLOWED="${SIGNUPS_ALLOWED:-true}"
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
    redir https://{host}:443{uri} permanent
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

##########  备份脚本  ##########
install_backup_script(){
  cat > /usr/local/bin/vw-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# 统一环境变量
source /etc/vaultwarden-backup.env
RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")

[[ -z "${RESTIC_IMAGE:-}" ]] && { echo "RESTIC_IMAGE 未设置，请检查 /etc/vaultwarden-backup.env"; exit 1; }

# 公共 docker 参数
COMMON=(--rm
        -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY"
        -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY"
        -e RESTIC_PASSWORD="$RESTIC_PASSWORD"
        -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET"
        -v "$DATA_DIR:/data:ro"
        -v "$SECRETS_FILE:/secrets.json:ro"
)

# 若仓库未初始化则先 init
if ! docker run "${COMMON[@]}" "$RESTIC_IMAGE" snapshots &>/dev/null; then
  echo "首次初始化 restic 仓库..."
  docker run "${COMMON[@]}" "$RESTIC_IMAGE" init || { echo "仓库初始化失败"; exit 1; }
fi

# 热备数据库并打包
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
sqlite3 "$DATA_DIR/db.sqlite3" ".backup '$TMP/db.sqlite3'"
rsync -a --exclude='*.tmp' --exclude='*.bak' "$DATA_DIR"/ "$TMP/"
cp "$SECRETS_FILE" "$TMP/"

# 备份 & 清理旧快照
docker run "${COMMON[@]}" -v "$TMP:/mnt" "$RESTIC_IMAGE" backup /mnt
docker run "${COMMON[@]}" "$RESTIC_IMAGE" forget --prune \
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --keep-yearly 3

echo "备份完成"
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

# 确保日志目录存在
mkdir -p "$(dirname "$LOG_FILE")"

# 单实例锁
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "【跳过】另一体检实例正在运行"
  exit 0
fi

# 日志函数
log(){
  echo "$(date '+%F %T') - $*" | tee -a "$LOG_FILE"
}

# 错误处理函数
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
  if docker compose ps | grep -q "Exited"; then
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
    # 运行时加载变量
    # shellcheck source=/dev/null
    source "$BACKUP_ENV"
    if [ -x /usr/local/bin/vw-backup ]; then
      bash -n /usr/local/bin/vw-backup || log_error_and_exit "备份脚本语法错误"
      log "✅ 备份脚本语法正确"
      
      # 从 SECRETS_FILE 读取 RESTIC_PASSWORD
      RESTIC_PASSWORD=$(jq -r '.RESTIC_PASSWORD' "$SECRETS_FILE")
      
      # 测试 restic 仓库是否已初始化
      output=$(docker run --rm \
        -e AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY" \
        -e AWS_SECRET_ACCESS_KEY="$R2_SECRET_KEY" \
        -e RESTIC_PASSWORD="$RESTIC_PASSWORD" \
        -e RESTIC_REPOSITORY="s3:$R2_ENDPOINT/$R2_BUCKET" \
        "$RESTIC_IMAGE" snapshots 2>&1)
      
      if [ $? -eq 0 ]; then
        log "✅ Restic 仓库已初始化"
      else
        log "⚠️  Restic 仓库检查失败: $output"
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
  log_info "已配置日志轮转：/etc/logrotate.d/vaultwarden"
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
  if docker compose ps | grep -q "Exited"; then
    log_err "检测到有已退出的容器（Exited），请检查容器日志：docker compose ps && docker compose logs"
    docker compose ps | tee -a "$INSTALL_LOG"
    docker compose logs --tail 50 | tee -a "$INSTALL_LOG"
    exit 1
  fi
  local tries=0
  until docker compose ps | grep -q "Up"; do
    sleep 2; ((tries++)); (( tries > 30 )) && { log_err "服务未能在超时时间内启动"; docker compose ps | tee -a "$INSTALL_LOG"; exit 1; }
    log_info "等待服务启动..."
  done
  log_ok "Vaultwarden ($ARCH) 已运行在 https://$VW_DOMAIN"
}

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
    log_err "已有另一个 Vaultwarden 安装脚本正在运行，请稍后再试。"
    exit 1
  fi
  log_info "已获得脚本执行锁"

  check_system
  check_vars
  ARCH=$(get_arch)
  log_info "开始安装 Vaultwarden ($ARCH)"
  install_deps
  init_dirs
  gen_creds
  gen_compose
  gen_caddyfile
  install_backup_script
  install_status_script
  setup_cron
  install_health_script
  setup_logrotate
  start_stack
  enable_autostart
  
  [[ "$SIGNUPS_ALLOWED" == "true" ]] && \
  log_warn "【安全提示】公网暴露时请记得关闭注册功能！"
  
  log_ok "安装完成！常用命令："
  log_info "  手动备份  : sudo vw-backup"
  log_info "  查看状态  : sudo vw-status"
  log_info "  每日体检  : sudo vw-health"
  log_info "  访问地址  : https://$VW_DOMAIN"
  log_info "  密钥文件  : $SECRETS_FILE"
  log_info "  安装日志  : $INSTALL_LOG"
}

main "$@"