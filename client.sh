#!/usr/bin/env bash
# ============================================================
#  PortMux 客户端(控制端)运行脚本 —— 纯运行, 不需要源码/Go/clang
#  使用前提: 同目录下已有 portmux-wrap 与 client.conf (生成器 portmux-gen 产出)
#  上传方式: 把生成器输出目录整目录拷贝到控制端
#  用法:     sudo ./client.sh [list|use 目标名|shell|socks|custom|env|help]
#           不带参数进入交互菜单 (自动读取 client.conf 生成目标菜单)
# ============================================================
set -u

RED=$(tput setaf 1 2>/dev/null || true); GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true); BLUE=$(tput setaf 4 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true); BOLD=$(tput bold 2>/dev/null || true)
NC=$(tput sgr0 2>/dev/null || true)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAP="$SCRIPT_DIR/portmux-wrap"
CONF="$SCRIPT_DIR/client.conf"
DEFAULT_KEY="portmux-key-2024"

step()  { echo "$BLUE[*]$NC $1"; }
ok()    { echo "$GREEN[√]$NC $1"; }
warn()  { echo "$YELLOW[!]$NC $1"; }
err()   { echo "$RED[×]$NC $1"; }
title() { echo "$BOLD$CYAN$1$NC"; }
die()   { err "$1"; exit 1; }

# ---------- root ----------
need_root_wrap() {
  if [ "$(id -u)" -ne 0 ]; then
    warn "wrap 需要 root (TCP_REPAIR 伪造 ISN), 正在通过 sudo 提权 (可能需要输入密码)..."
    exec sudo bash "$(readlink -f "$0")" "$@"
  fi
}

unquote() {
  local v="$1" q='"'
  v="${v#"$q"}"
  v="${v%"$q"}"
  q="'"
  v="${v#"$q"}"
  v="${v%"$q"}"
  printf '%s' "$v"
}

# ---------- 解析 client.conf (生成器产出的固定 YAML 格式) ----------
#   default: <name>
#   targets:
#     - name: <name>
#       host: <ip>
#       port: <n>
#       key: <key>
#       fingerprint: <fp>
#       mode: shell|socks5|custom
#       exec/args: ...
CONF_NAMES=(); CONF_HOSTS=(); CONF_PORTS=(); CONF_KEYS=(); CONF_FPS=(); CONF_MODES=(); CONF_DEFAULT=""
CONF_COUNT=0

load_conf() {
  CONF_NAMES=(); CONF_HOSTS=(); CONF_PORTS=(); CONF_KEYS=(); CONF_FPS=(); CONF_MODES=(); CONF_DEFAULT=""
  CONF_COUNT=0
  [ -f "$CONF" ] || return 1
  local line
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"   # 去前导空白
    line="${line#- }"                           # 去列表 "- "
    case "$line" in
      default:*)     v="${line#default:}"; v="${v# }"; CONF_DEFAULT=$(unquote "$v") ;;
      name:*)        v="${line#name:}"; v="${v# }"; CONF_NAMES+=("$(unquote "$v")"); CONF_COUNT=$((CONF_COUNT+1)) ;;
      host:*)        v="${line#host:}"; v="${v# }"; CONF_HOSTS+=("$(unquote "$v")") ;;
      port:*)        v="${line#port:}"; v="${v# }"; CONF_PORTS+=("$(unquote "$v")") ;;
      key:*)         v="${line#key:}"; v="${v# }"; CONF_KEYS+=("$(unquote "$v")") ;;
      fingerprint:*) v="${line#fingerprint:}"; v="${v# }"; CONF_FPS+=("$(unquote "$v")") ;;
      mode:*)        v="${line#mode:}"; v="${v# }"; CONF_MODES+=("$(unquote "$v")") ;;
      *) ;;
    esac
  done < "$CONF"
  [ "$CONF_COUNT" -gt 0 ]
}

conf_show() {
  local i idx
  for ((i=1; i<=CONF_COUNT; i++)); do
    idx=$((i-1))
    printf "  %2d) %-16s %s:%s  mode=%s
" "$i" "${CONF_NAMES[$idx]}" "${CONF_HOSTS[$idx]}" "${CONF_PORTS[$idx]}" "${CONF_MODES[$idx]}"
  done
}

find_name() {
  local i idx
  for ((i=1; i<=CONF_COUNT; i++)); do
    idx=$((i-1))
    [ "${CONF_NAMES[$idx]}" = "$1" ] && { echo "$i"; return 0; }
  done
  echo "0"
  return 1
}

conf_run() {
  local idx=$1
  idx=$((idx-1))
  local name="${CONF_NAMES[$idx]}"
  local mode="${CONF_MODES[$idx]}"
  [ -n "$name" ] || die "目标不存在"
  need_root_wrap conf "$name"
  if [ "$mode" = "socks5" ]; then
    step "SOCKS5 目标: 将自动监听 127.0.0.1:1080 (可改 -listen, 用法见 socks 说明)"
    socks_usage
  fi
  step "连接目标 $name (${CONF_HOSTS[$idx]}:${CONF_PORTS[$idx]}, mode=$mode)..."
  exec "$WRAP" -target "$name" -conf "$CONF"
}

do_use() {
  local di
  di=$(find_name "$1")
  [ "$di" != "0" ] || die "目标 $1 不在 client.conf 中 (先执行 $0 list 查看)"
  conf_run "$di"
}

ask_target() {
  read -p "$YELLOW 目标地址 host:port (如 192.0.2.10:80): $NC" target
  [ -z "$target" ] && die "必须指定目标地址"
  read -p "$YELLOW magic_key [默认 $DEFAULT_KEY]: $NC" ans
  [ -z "$ans" ] && ans="$DEFAULT_KEY"
  mkey="$ans"
}

# ---------- 模式1: 直接连接 shell ----------
do_shell() {
  ask_target
  need_root_wrap shell-auto "$target" "$mkey"
  exec "$WRAP" -target "$target" -key "$mkey"
}
do_shell_auto() {
  exec "$WRAP" -target "$1" -key "$2"
}

# ---------- 模式2: 本地 SOCKS5 转发 ----------
do_socks() {
  ask_target
  local listen="127.0.0.1:1080"
  read -p "$YELLOW 本地监听地址 [默认 $listen]: $NC" ans
  [ -n "$ans" ] && listen="$ans"
  need_root_wrap socks-auto "$target" "$mkey" "$listen"
  step "启动本地 SOCKS5 转发服务 (Ctrl+C 停止)..."
  exec "$WRAP" -listen "$listen" -target "$target" -key "$mkey"
}
do_socks_auto() {
  exec "$WRAP" -listen "$3" -target "$1" -key "$2"
}

socks_usage() {
  echo
  title "== SOCKS5 内网穿透用法 =="
  echo "  1. 本工具已把远端 agent 的 socks5 能力转发到本地端口"
  echo "  2. 安装 proxychains:  sudo apt install -y proxychains4"
  echo "  3. 编辑 /etc/proxychains4.conf 末尾增加一行:"
  echo "       $GREEN socks5 127.0.0.1 <本地端口>$NC"
  echo "  4. 用法示例:"
  echo "       $GREEN proxychains4 nmap -sT -Pn 10.0.0.0/24$NC"
  echo "       $GREEN proxychains4 curl http://内网服务/$NC"
  echo "  5. 注意: 保持本窗口运行, 每个新连接都会走 magic ISN 敲门"
  echo
}

# ---------- 模式3: 自定义程序 ----------
do_custom() {
  ask_target
  read -p "$YELLOW 要运行的程序路径 [默认 /bin/sh]: $NC" prog
  [ -z "$prog" ] && prog="/bin/sh"
  read -p "$YELLOW 程序参数 (可空): $NC" args
  need_root_wrap custom-auto "$target" "$mkey" "$prog" "$args"
  exec "$WRAP" -target "$target" -key "$mkey" -exec "$prog" -args "$args"
}
do_custom_auto() {
  exec "$WRAP" -target "$1" -key "$2" -exec "$3" -args "$4"
}

# ---------- 环境检查 ----------
do_env() {
  title "== 客户端环境检查 =="
  echo "$CYAN[1] sudo:$NC $([ -n "$(command -v sudo)" ] && echo "可用 (wrap 需要 root)" || echo "不可用")"
  echo "$CYAN[2] wrap 二进制:$NC $([ -x "$WRAP" ] && echo "存在 ($WRAP)" || echo "缺失! 需上传生成器输出目录")"
  echo "$CYAN[3] client.conf:$NC $([ -f "$CONF" ] && echo "存在 ($CONF)" || echo "缺失 (不影响手动模式)")"
  echo "$CYAN[4] proxychains:$NC $([ -n "$(command -v proxychains4)" ] && echo "可用" || echo "未安装 (SOCKS5 模式建议: sudo apt install -y proxychains4)")"
  echo
}

usage() {
  echo "用法: $0 [list|use 目标名|shell|socks|custom|env|help]"
  echo "  list        列出 client.conf 里的目标"
  echo "  use 目标名  直接连接 client.conf 中名为 目标名 的配置 (自动取 key/指纹/模式)"
  echo "  shell       手动指定 host:port + key 连接连接 shell"
  echo "  socks       手动模式: 本地 SOCKS5 转发 (proxychains 内网穿透)"
  echo "  custom      手动模式: 连接并运行自定义程序 (如 ssh)"
  echo "  env         环境检查"
  echo "  不带参数    进入交互菜单 (自动读取 client.conf 生成目标菜单)"
}

manual_menu() {
  echo "  $GREEN 1)$NC shell   直接连接目标连接 shell"
  echo "  $GREEN 2)$NC socks   本地 SOCKS5 转发 (proxychains 内网穿透)"
  echo "  $GREEN 3)$NC custom  自定义程序 (如 ssh)"
  echo "  $GREEN 4)$NC env     环境检查"
  echo "  $GREEN 0)$NC exit    退出"
  read -p "$YELLOW 请输入序号: $NC" ans
  case "$ans" in
    1) do_shell ;;
    2) do_socks ;;
    3) do_custom ;;
    4) do_env ;;
    0) exit 0 ;;
    *) warn "无效选择" ;;
  esac
}

menu() {
  title "=============================================="
  title "   PortMux 客户端(控制端) 运行工具"
  title "=============================================="
  if load_conf; then
    echo "  $CYAN已读取 client.conf:$NC $CONF_COUNT 个目标 (默认: ${CONF_DEFAULT:-无})"
    echo
    conf_show
    echo
    echo "  $GREEN m)$NC 手动指定目标 (host:port + key)"
    echo "  $GREEN e)$NC env    $GREEN s)$NC help    $GREEN 0)$NC exit"
    read -p "$YELLOW 请输入目标序号 (回车=默认目标): $NC" ans
    case "$ans" in
      "")
        if [ -n "$CONF_DEFAULT" ]; then
          local di
          di=$(find_name "$CONF_DEFAULT")
          [ "$di" != "0" ] && conf_run "$di"
          warn "默认目标 $CONF_DEFAULT 不在 client.conf 中"
        else
          warn "无默认目标, 请输入序号"
        fi ;;
      m) manual_menu ;;
      e) do_env ;;
      s) usage ;;
      0) exit 0 ;;
      *)
        if [ "$ans" -ge 1 ] 2>/dev/null && [ "$ans" -le "$CONF_COUNT" ] 2>/dev/null; then
          conf_run "$ans"
        else
          warn "无效选择"
        fi ;;
    esac
  else
    warn "未找到 client.conf ($CONF) —— 使用手动模式"
    echo
    manual_menu
  fi
}

case "${1:-}" in
  list)       load_conf && conf_show || die "未找到 client.conf ($CONF)"; exit 0 ;;
  use)        load_conf || die "未找到 client.conf ($CONF)"; do_use "${2:-}" ;;
  shell)      do_shell ;;
  shell-auto) do_shell_auto "$2" "$3" ;;
  socks)      do_socks ;;
  socks-auto) do_socks_auto "$2" "$3" "$4" ;;
  custom)     do_custom ;;
  custom-auto) do_custom_auto "$2" "$3" "$4" "$5" ;;
  env)        do_env ;;
  help|-h)    usage ;;
  "")         menu ;;
  *)          warn "未知参数: $1"; usage; exit 1 ;;
esac
