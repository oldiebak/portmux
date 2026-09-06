#!/usr/bin/env bash
# ============================================================
#  PortMux 服务端(目标机)部署脚本 —— 纯部署, 不需要源码/Go/clang
#  使用前提: 同目录下已有生成器产出的 server-*.pm 二进制 (编译机 build.sh → 控制端 portmux-gen)
#  上传方式: scp server-XXXXXXXX.pm root@目标机:/opt/portmux/
#  用法:     sudo ./server.sh [start|stop|status|cleanup|env|help]
#           不带参数进入交互菜单
#  zero-config: server-*.pm 内置完整配置 (--PMCFG1-- 块) 时, start 零交互直接启动
# ============================================================
set -u

RED=$(tput setaf 1 2>/dev/null || true); GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true); BLUE=$(tput setaf 4 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true); BOLD=$(tput bold 2>/dev/null || true)
NC=$(tput sgr0 2>/dev/null || true)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# 生成器产出的目标端二进制: 优先 server-*.pm, 兼容旧版 .pm
PM_BIN=""
for f in "$SCRIPT_DIR"/server-*.pm; do
  [ -x "$f" ] && { PM_BIN="$f"; break; }
done
[ -z "$PM_BIN" ] && [ -x "$SCRIPT_DIR/.pm" ] && PM_BIN="$SCRIPT_DIR/.pm"

RT_CFG="/tmp/portmux-rt.yaml"                  # 运行时覆盖配置 (网卡/端口/密钥)
PID_FILE="/tmp/portmux-agent.pid"
LOG_FILE="/tmp/portmux-agent.log"
QDISC_FLAG="/tmp/portmux-agent.created_qdisc"  # 标记 clsact 由我们创建

step()  { echo "$BLUE[*]$NC $1"; }
ok()    { echo "$GREEN[√]$NC $1"; }
warn()  { echo "$YELLOW[!]$NC $1"; }
err()   { echo "$RED[×]$NC $1"; }
title() { echo "$BOLD$CYAN$1$NC"; }
die()   { err "$1"; exit 1; }

ask_yn() {
  if [ "${PORTMUX_YES:-}" = "1" ]; then echo "y"; return; fi
  read -p "$YELLOW $1 [y/N]: $NC" ans
  echo "$ans"
}

# ---------- root ----------
need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    warn "该操作需要 root 权限 (tc / iptables / BPF), 正在通过 sudo 提权 (可能需要输入密码)..."
    exec sudo bash "$(readlink -f "$0")" "$@"
  fi
}

detect_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

# ---------- 运行依赖 ----------
check_run_deps() {
  step "检查运行依赖..."
  local missing=""
  command -v tc >/dev/null 2>&1 || missing="$missing iproute2(tc)"
  command -v iptables >/dev/null 2>&1 || missing="$missing iptables"
  command -v ip >/dev/null 2>&1 || missing="$missing ip"
  if [ -n "$missing" ]; then
    warn "缺少运行依赖:$missing"
    ans=$(ask_yn "是否通过 apt 安装 (需要 sudo)?")
    if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then die "缺少依赖"; fi
    sudo apt-get install -y iproute2 iptables || die "apt 安装失败"
  fi
  ok "运行依赖齐全"
}

# ---------- 启动 ----------
do_start() {
  need_root "$@"
  if [ -z "$PM_BIN" ] || [ ! -x "$PM_BIN" ]; then
    die "未找到 server-*.pm —— 请把生成器(portmux-gen)产出的 server-XXXXXXXX.pm 与本脚本放到同一目录后重试"
  fi
  check_run_deps || return 1

  local iface ans ports mkey CFG_YAML=""
  iface=$(detect_iface)
  [ -z "$iface" ] && iface="ens18"
  if grep -qa -- '--PMCFG1--' "$PM_BIN"; then
    ok "检测到内置完整配置 (二进制尾部 --PMCFG1-- 块): 零交互启动, 网卡/端口/密钥来自二进制"
  else
    title "== PortMux 部署配置 =="
    step "以下配置直接回车使用默认值 (规则已编译在二进制内, 这里只指定网卡/端口/密钥):"
    if [ -z "${PORTMUX_IFACE:-}" ]; then
      read -p "$YELLOW 监听网卡 [默认: $iface]: $NC" ans
      [ -n "$ans" ] && iface="$ans"
    else
      iface="$PORTMUX_IFACE"
    fi
    if [ -n "${PORTMUX_PORTS:-}" ]; then
      ports="$PORTMUX_PORTS"
    else
      read -p "$YELLOW 劫持端口, 逗号分隔 (填正在提供正常服务的端口, 如 80 或 80,443) [默认: 80]: $NC" ans
      [ -z "$ans" ] && ans="80"
      ports="$ans"
    fi
    if [ -n "${PORTMUX_KEY:-}" ]; then
      mkey="$PORTMUX_KEY"
    else
      read -p "$YELLOW magic_key 密钥 (需与客户端一致) [默认: portmux-key-2024]: $NC" ans
      [ -z "$ans" ] && ans="portmux-key-2024"
      mkey="$ans"
    fi
    CFG_YAML="magic_key: \"$mkey\"
listen:
  iface: \"$iface\"
  watch_ports: [$ports]"
    printf '%b' "$CFG_YAML" > "$RT_CFG"
    ok "运行时配置已生成 → $RT_CFG"
    cat "$RT_CFG"
  fi

  if ! tc qdisc show dev "$iface" 2>/dev/null | grep -q clsact; then
    tc qdisc add dev "$iface" clsact || die "创建 clsact qdisc 失败"
    touch "$QDISC_FLAG"
    ok "已创建 clsact qdisc (已记录, 清理时会自动删除)"
  fi

  # 记录 route_localnet 启动前快照 (agent 被 SIGKILL 时的兜底还原依据)
  cat /proc/sys/net/ipv4/conf/all/route_localnet > /tmp/portmux-rl-all.orig 2>/dev/null
  cat "/proc/sys/net/ipv4/conf/$iface/route_localnet" > /tmp/portmux-rl-iface.orig 2>/dev/null

  step "启动 Agent... (零参数启动, ps 看不到任何参数)"
  # setsid: 脱离当前会话/进程组, 避免 ssh 会话结束或父 shell 退出时被连带终止
  if [ -n "$CFG_YAML" ]; then
    setsid nohup env PORTMUX_DAEMON=1 PORTMUX_CONFIG_YAML="$CFG_YAML" "$PM_BIN" >> "$LOG_FILE" 2>&1 &
  else
    setsid nohup env PORTMUX_DAEMON=1 "$PM_BIN" >> "$LOG_FILE" 2>&1 &
  fi
  echo $! > "$PID_FILE"
  sleep 2
  if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "Agent 已启动, PID=$(cat "$PID_FILE")"
    ok "日志查看: tail -f $LOG_FILE"
    step "客户端(控制端)用法: 在生成器输出目录执行 ./client.sh 选择目标"
  else
    err "Agent 启动失败, 日志如下:"
    cat "$LOG_FILE"
    exit 1
  fi
}

# ---------- 停止 ----------
do_stop() {
  need_root "$@"
  local pid=""
  [ -f "$PID_FILE" ] && pid=$(cat "$PID_FILE")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    step "发送 SIGTERM 停止 Agent (会自动清理 tc/iptables)..."
    kill -TERM "$pid"
    local i
    for i in 1 2 3 4 5; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      warn "进程未退出, 强制结束"
      kill -KILL "$pid" 2>/dev/null
    fi
    ok "Agent 已停止 (PID=$pid)"
  else
    ok "Agent 未在运行"
  fi
  rm -f "$PID_FILE"
  step "执行兜底清理 (tc/iptables/临时文件)..."
  do_cleanup_quiet
}

# ---------- 静默清理 ----------
do_cleanup_quiet() {
  local iface=""
  if [ -f "$RT_CFG" ]; then
    iface=$(grep -E '^\s*iface:' "$RT_CFG" | head -1 | sed 's/.*iface: *"\([^"]*\)".*/\1/')
  fi
  [ -z "$iface" ] && iface=$(detect_iface)
  [ -z "$iface" ] && iface="ens18"
  if [ -n "$iface" ]; then
    local pref
    pref=$(cat /tmp/portmux-agent.pref 2>/dev/null || echo 0x706d)
    tc filter del dev "$iface" ingress pref "$pref" 2>/dev/null
    if [ -f "$QDISC_FLAG" ]; then
      tc qdisc del dev "$iface" clsact 2>/dev/null
      rm -f "$QDISC_FLAG"
    fi
  fi
  iptables -t nat -S PREROUTING 2>/dev/null | grep -E 'portmux|0x706d0001' | grep -E 'REDIRECT|DNAT' | sed 's/^-A/-D/' | while read -r rule; do
    iptables -t nat $rule 2>/dev/null
  done
  # 兜底: 清除 pinned map (agent 被 SIGKILL 时 Cleanup 不会执行, 防止节流等状态残留)
  for pfx in pc pw ps kn pt pd hp hg db pg se sx ke kx sec secl sk pi pl; do
    rm -f /sys/fs/bpf/tc/globals/${pfx}_* 2>/dev/null
  done
  # 兜底: 恢复 route_localnet (agent 被 SIGKILL 时 Cleanup 不会执行; 按启动前快照还原)
  if [ -f /tmp/portmux-rl-all.orig ]; then
    sysctl -w net.ipv4.conf.all.route_localnet="$(cat /tmp/portmux-rl-all.orig)" 2>/dev/null
  fi
  if [ -n "$iface" ] && [ -f /tmp/portmux-rl-iface.orig ]; then
    sysctl -w "net.ipv4.conf.$iface.route_localnet=$(cat /tmp/portmux-rl-iface.orig)" 2>/dev/null
  fi
  rm -f /tmp/portmux-rl-all.orig /tmp/portmux-rl-iface.orig
  rm -f /tmp/portmux.bpf.o "$PID_FILE" "$RT_CFG" "$LOG_FILE" /tmp/portmux-agent.pref /tmp/portmux-agent.created_qdisc
}

# ---------- 清理还原 ----------
do_cleanup() {
  need_root "$@"
  step "清理 PortMux 环境..."
  do_cleanup_quiet
  ok "清理完成"
  echo
  step "验证还原结果:"
  echo "$CYAN--- 本工具相关 tc filter (应为空) ---$NC"
  tc filter show dev "$(detect_iface)" ingress 2>/dev/null | grep -E '0x706d|bpf' || echo "  (无)"
  echo "$CYAN--- 本工具相关 iptables 规则 (应为空) ---$NC"
  iptables -t nat -S PREROUTING 2>/dev/null | grep -E 'portmux|0x706d0001' || echo "  (无)"
  echo "$CYAN--- 临时文件 ---$NC"
  ls /tmp/portmux* 2>/dev/null || echo "  (无)"
  ok "环境已还原, 原有服务不受影响"
}

# ---------- 状态 ----------
do_status() {
  local pid=""
  [ -f "$PID_FILE" ] && pid=$(cat "$PID_FILE")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    ok "Agent 运行中 (PID=$pid)"
    ps -o pid,ppid,user,comm,args -p "$pid" 2>/dev/null | tail -1
  else
    warn "Agent 未运行"
  fi
  echo "$CYAN--- tc filter (pref 0x706d) ---$NC"
  tc filter show dev "$(detect_iface)" ingress 2>/dev/null | grep -B1 -A3 0x706d || echo "  (无)"
  echo "$CYAN--- iptables 规则 ---$NC"
  iptables -t nat -S PREROUTING 2>/dev/null | grep -E 'portmux|0x706d0001' || echo "  (无)"
  echo "$CYAN--- 日志尾部 ---$NC"
  [ -f "$LOG_FILE" ] && tail -5 "$LOG_FILE" || echo "  (无日志)"
}

# ---------- 环境检查 ----------
do_env() {
  title "== 环境检查 =="
  echo "$CYAN[1] 权限:$NC $([ "$(id -u)" = 0 ] && echo "root" || echo "非 root (部署时自动 sudo)")"
  echo "$CYAN[2] 内核:$NC $(uname -r) (需 >= 5.4)"
  echo "$CYAN[3] BTF:$NC $([ -f /sys/kernel/btf/vmlinux ] && echo "存在" || echo "缺失")"
  echo "$CYAN[4] bpffs:$NC $([ -n "$(mount | grep bpf)" ] && echo "已挂载" || echo "未挂载")"
  echo "$CYAN[5] tc/iptables:$NC $([ -n "$(command -v tc)" ] && echo -n "tc有 " || echo -n "tc缺 ")$([ -n "$(command -v iptables)" ] && echo "iptables有" || echo "iptables缺")"
  echo "$CYAN[6] agent 二进制:$NC $([ -n "$PM_BIN" ] && [ -x "$PM_BIN" ] && echo "存在 ($PM_BIN)" || echo "缺失! 需把生成器产出的 server-*.pm 上传到本目录")"
  echo "$CYAN[7] 默认网卡:$NC $(detect_iface)"
  echo "$CYAN[8] 正在监听的 TCP 端口:$NC"
  ss -tln 2>/dev/null | tail -n +2 | awk '{print $4}' | sort -u | head -20 | sed 's/^/    /'
  echo
  step "提示: 劫持端口应填正在提供正常服务的端口, 后端服务须本机可连"
}

usage() {
  echo "用法: $0 [start|stop|status|cleanup|env|help]"
  echo "  start    部署并启动 (内置配置时零交互, 自动 sudo)"
  echo "  stop     停止 Agent 并清理环境"
  echo "  status   查看运行状态 (tc/iptables/日志)"
  echo "  cleanup  清理还原环境 (不影响原有服务)"
  echo "  env      环境检查"
  echo "  不带参数 进入交互菜单"
}

menu() {
  title "=============================================="
  title "   PortMux 服务端(目标机) 部署工具"
  title "=============================================="
  echo "  $GREEN 1)$NC start     部署并启动 (自动 sudo 提权)"
  echo "  $GREEN 2)$NC stop      停止 Agent 并清理"
  echo "  $GREEN 3)$NC status    查看状态"
  echo "  $GREEN 4)$NC cleanup   清理还原环境"
  echo "  $GREEN 5)$NC env       环境检查"
  echo "  $GREEN 6)$NC help      帮助"
  echo "  $GREEN 0)$NC exit      退出"
  read -p "$YELLOW 请输入序号: $NC" ans
  case "$ans" in
    1) do_start ;;
    2) do_stop ;;
    3) do_status ;;
    4) do_cleanup ;;
    5) do_env ;;
    6) usage ;;
    0) exit 0 ;;
    *) warn "无效选择" ;;
  esac
}

case "$1" in
  start)   do_start "$@" ;;
  stop)    do_stop "$@" ;;
  status)  do_status ;;
  cleanup) do_cleanup "$@" ;;
  env)     do_env ;;
  help|-h) usage ;;
  "")      menu ;;
  *)       warn "未知参数: $1"; usage; exit 1 ;;
esac
