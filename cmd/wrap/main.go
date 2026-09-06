package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"portmux/internal/cryptoio"
)

var (
	target      = flag.String("target", "", "target host:port")
	key         = flag.String("key", "portmux-key-2024", "magic key (must match agent)")
	fingerprint = flag.String("fingerprint", "auto", "bytes to send after connect. auto|none|literal (hex escapes \\xNN supported)")
	listenAddr  = flag.String("listen", "", "local SOCKS5 relay mode: listen addr (e.g. 127.0.0.1:1080), forward each connection to -target via magic ISN")
	cryptoOn    = flag.Bool("crypto", true, "enable stream encryption (XChaCha20-Poly1305, key derived from -key)")
	prog        = flag.String("exec", "", "program to run (default: /bin/sh)")
	execArgs    = flag.String("args", "", "arguments for program")
	confPath    = flag.String("conf", "", "client.conf path (default: auto-detect ./client.conf)")
	listMode    = flag.Bool("list", false, "list targets in client.conf")
)

var flagKeySet bool

func main() {
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "key" {
			flagKeySet = true
		}
	})

	// 解析 client.conf (多目标配置文件)
	conf := loadClientConf(*confPath)
	if *listMode {
		if conf == nil {
			fatal(fmt.Errorf("未找到 client.conf (可用 -conf 指定路径)"))
		}
		fmt.Fprintf(os.Stderr, "可用目标 (%d 个, 默认 %q):\n", len(conf.Targets), conf.Default)
		for _, p := range conf.Targets {
			fmt.Fprintf(os.Stderr, "  %-16s %s:%d  mode=%s\n", p.Name, p.Host, p.Port, p.Mode)
		}
		return
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: portmux-wrap -target host:port [-fingerprint auto|none|literal] [-key key] [-crypto=false] [-listen addr] [-exec prog] [-args args]")
		fmt.Fprintln(os.Stderr, "  或按名字: portmux-wrap -target <名字> -conf client.conf")
		fmt.Fprintln(os.Stderr, "  列目标:   portmux-wrap -list [-conf client.conf]")
		fmt.Fprintln(os.Stderr, "  example: portmux-wrap -target 192.0.2.10:80 -key <magic_key>")
		os.Exit(1)
	}

	// -target 优先按 client.conf 里的 profile 名解析, 否则按 host:port
	var host, port string
	if p, ok := findProfile(*target, conf); ok {
		host, port = p.Host, fmt.Sprintf("%d", p.Port)
		if p.Key != "" && !flagKeySet {
			*key = p.Key
		}
		if *fingerprint == "auto" && p.Fingerprint != "" {
			*fingerprint = p.Fingerprint
		}
		if p.Mode == "socks5" && *listenAddr == "" {
			// socks5 目标需要本地转发, 默认监听 1080
			*listenAddr = "127.0.0.1:1080"
		}
		if *prog == "" && p.Exec != "" {
			*prog = p.Exec
		}
		if *execArgs == "" && p.Args != "" {
			*execArgs = p.Args
		}
		fmt.Fprintf(os.Stderr, "[*] 目标 %s → %s:%s\n", p.Name, host, port)
	} else {
		var err error
		host, port, err = net.SplitHostPort(*target)
		if err != nil {
			fatal(err)
		}
	}

	magicPrefix := deriveMagic(*key)
	cryptoKey := cryptoio.DeriveKey(*key)

	if *listenAddr != "" {
		fmt.Fprintf(os.Stderr, "[*] local SOCKS5 relay mode\n[*] listen %s → magic-ISN → %s:%s (magic=0x%04x, crypto=%v)\n",
			*listenAddr, host, port, magicPrefix, *cryptoOn)
		if err := runLocalRelay(*listenAddr, host, port, magicPrefix, cryptoKey); err != nil {
			fatal(err)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "[*] connecting %s:%s (magic=0x%04x, crypto=%v)\n", host, port, magicPrefix, *cryptoOn)

	fd, err := dialMagic(host, port, magicPrefix)
	if err != nil {
		fatal(err)
	}

	banner := resolveBanner(*fingerprint)
	if len(banner) > 0 {
		if _, err := unix.Write(fd, banner); err != nil {
			fatal(fmt.Errorf("send fingerprint: %w", err))
		}
		fmt.Fprintf(os.Stderr, "[*] fingerprint sent (%d bytes: %q)\n", len(banner), printable(banner))
	}

	// 指纹之后的数据流加密
	nc, err := net.FileConn(os.NewFile(uintptr(fd), "magic"))
	if err != nil {
		fatal(err)
	}
	defer nc.Close()
	var stream io.ReadWriteCloser = nc
	if *cryptoOn {
		ec, err := cryptoio.New(nc, cryptoKey)
		if err != nil {
			fatal(err)
		}
		stream = rwcWrap{ec, ec, ec}
	}

	// ---- 无 -exec: 本机 stdio ↔ 远端 shell (交互终端 / 管道均可用) ----
	if *prog == "" {
		// 终端 raw 模式: 本机不再回显, 由远端 PTY 统一处理
		restore, ttyErr := rawMode(0)
		if ttyErr == nil && restore != nil {
			defer restore()
		}
		bridgeDone := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(stream, os.Stdin) // 本机输入 → 远端 PTY
			// 输入 EOF (Ctrl-D / 管道结束): 给远端一点时间执行命令并回传输出
			time.Sleep(1500 * time.Millisecond)
			_ = stream.Close()
			bridgeDone <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(os.Stdout, stream) // 远端输出 → 本机终端
			bridgeDone <- struct{}{}
		}()
		<-bridgeDone
		return
	}

	// ---- -exec 模式: 本地程序 stdio ↔ 远端 (驱动/脚本用) ----
	execProgram := *prog
	args := []string{execProgram}
	if *execArgs != "" {
		args = append(args, splitArgs(*execArgs)...)
	}

	cmd := exec.Command(execProgram, args[1:]...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		fatal(err)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		fatal(err)
	}
	childErr, err := cmd.StderrPipe()
	if err != nil {
		fatal(err)
	}
	if err := cmd.Start(); err != nil {
		fatal(err)
	}

	done := make(chan struct{}, 3)
	go func() {
		_, _ = io.Copy(childIn, stream) // 远端 → 子进程 stdin
		childIn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, childOut) // 子进程 stdout → 远端 (加密)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, childErr) // 子进程 stderr → 远端 (加密)
		done <- struct{}{}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case <-waitCh:
	case <-done:
		// 连接断开, 结束子进程
		cmd.Process.Kill()
		<-waitCh
	}
}

// rwcWrap 把 cryptoio.EncryptedConn 适配成 io.ReadWriteCloser
type rwcWrap struct {
	io.Reader
	io.Writer
	io.Closer
}

// rawMode 把 fd 设为 raw 终端 (无本地回显/无行缓冲), 返回恢复函数
func rawMode(fd int) (func(), error) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *t
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return func() {
		unix.IoctlSetTermios(fd, unix.TCSETS, t)
	}, nil
}

// runLocalRelay 本地 SOCKS5 转发: 接受本地连接 → magic ISN 连目标 → 发 socks5 指纹 →
// 之后双向加密转发(远端 agent 的 socks5 handler 负责解析 CONNECT)。
func runLocalRelay(addr, host, port string, magic uint16, cryptoKey []byte) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	i := strings.LastIndex(addr, ":")
	fmt.Fprintf(os.Stderr, "[*] proxychains 配置: socks5 127.0.0.1 %s\n", addr[i+1:])

	for {
		client, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			fd, err := dialMagic(host, port, magic)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] relay dial: %v\n", err)
				return
			}
			up := os.NewFile(uintptr(fd), "magic")
			// 明文指纹必须与规则指纹长度完全一致 (\x05\x01\x00 = 3 字节):
			// 加密模式下方法字节(00)走加密流, 否则明文指纹多出的字节会
			// 混入加密帧头导致解密错位
			fp := []byte{0x05, 0x01, 0x00}
			if !*cryptoOn {
				fp = append(fp, 0x00)
			}
			if _, err := up.Write(fp); err != nil {
				fmt.Fprintf(os.Stderr, "[!] relay fp: %v\n", err)
				up.Close()
				return
			}
			unc, err := net.FileConn(up)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] relay fileconn: %v\n", err)
				up.Close()
				return
			}
			defer unc.Close()
			var upStream io.ReadWriteCloser = unc
			if *cryptoOn {
				ec, err := cryptoio.New(unc, cryptoKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] relay crypto: %v\n", err)
					return
				}
				upStream = rwcWrap{ec, ec, ec}
				// 加密模式下明文指纹只用于路由(已被消费), 远端 handler 的
				// greeting 协议发生在加密流上, 需要再发一份
				if _, err := upStream.Write([]byte{0x05, 0x01, 0x00, 0x00}); err != nil {
					fmt.Fprintf(os.Stderr, "[!] relay greeting: %v\n", err)
					return
				}
				fmt.Fprintf(os.Stderr, "[*] relay: encrypted greeting sent\n")
			}
			// 消费远端 handler 的 greeting 应答 (0500)
			upReply := make([]byte, 2)
			if _, err := io.ReadFull(upStream, upReply); err != nil {
				fmt.Fprintf(os.Stderr, "[!] relay upreply: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "[*] relay: remote greeting reply % x\n", upReply)
			// 本地终结客户端 greeting 阶段
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(c, hdr); err != nil {
				fmt.Fprintf(os.Stderr, "[!] relay client hdr: %v\n", err)
				return
			}
			if hdr[0] != 0x05 {
				fmt.Fprintf(os.Stderr, "[!] relay bad ver: %d\n", hdr[0])
				return
			}
			methods := make([]byte, int(hdr[1]))
			if _, err := io.ReadFull(c, methods); err != nil {
				return
			}
			if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
				return
			}
			done := make(chan struct{}, 2)
			go func() { io.Copy(upStream, c); done <- struct{}{} }()
			go func() { io.Copy(c, upStream); done <- struct{}{} }()
			<-done
		}(client)
	}
}

func resolveBanner(fp string) []byte {
	switch fp {
	case "auto":
		if *prog == "" {
			if *cryptoOn {
				// 加密模式下明文指纹只用于路由, 必须与规则指纹等长,
				// 多发的字节会被当成密文帧头导致流错位
				return []byte("SSH-2.0")
			}
			return []byte("SSH-2.0\r\n")
		}
		return nil
	case "none", "":
		return nil
	default:
		return parseFingerprint(fp)
	}
}

func parseFingerprint(fp string) []byte {
	var result []byte
	i := 0
	for i < len(fp) {
		if fp[i] == '\\' && i+3 < len(fp) && fp[i+1] == 'x' {
			result = append(result, hexDigit(fp[i+2])<<4|hexDigit(fp[i+3]))
			i += 4
		} else {
			result = append(result, fp[i])
			i++
		}
	}
	return result
}

func hexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func printable(b []byte) string {
	s := ""
	for _, c := range b {
		if c >= 32 && c < 127 {
			s += string(c)
		} else {
			s += fmt.Sprintf("\\x%02x", c)
		}
	}
	return s
}

func deriveMagic(k string) uint16 {
	h := sha256.Sum256([]byte(k))
	return binary.BigEndian.Uint16(h[:2])
}

func dialMagic(host, port string, magic uint16) (int, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return 0, err
	}
	ip := ips[0].To4()
	if ip == nil {
		return 0, fmt.Errorf("need IPv4")
	}

	portInt := 0
	fmt.Sscanf(port, "%d", &portInt)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return 0, err
	}

	addr := &unix.SockaddrInet4{Port: portInt}
	copy(addr.Addr[:], ip)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 1); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("TCP_REPAIR (enter): %w (need root)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 2); err != nil {
		unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0)
		unix.Close(fd)
		return 0, fmt.Errorf("TCP_REPAIR_QUEUE: %w", err)
	}

	rand16, _ := rand.Int(rand.Reader, big.NewInt(65535))
	isn := uint32(magic)<<16 | uint32(rand16.Uint64())
	isnBuf := make([]byte, 4)
	// 内核 copy_from_sockptr 按【本机字节序】读 TCP_QUEUE_SEQ
	binary.NativeEndian.PutUint32(isnBuf, isn)

	if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ, string(isnBuf)); err != nil {
		unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0)
		unix.Close(fd)
		return 0, fmt.Errorf("TCP_QUEUE_SEQ: %w", err)
	}

	// 现代内核: repair 模式下 connect 不发送 SYN, 必须先退出 repair 再 connect
	unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 0)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("TCP_REPAIR (exit): %w", err)
	}
	if err := unix.Connect(fd, addr); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("connect: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[*] connected (ISN=0x%08x)\n", isn)
	return fd, nil
}

func splitArgs(s string) []string {
	var args []string
	inQuote := false
	current := ""
	for _, c := range s {
		switch {
		case c == '\'' || c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current != "" {
				args = append(args, current)
				current = ""
			}
		default:
			current += string(c)
		}
	}
	if current != "" {
		args = append(args, current)
	}
	return args
}

// ---- client.conf (多目标配置) ----

type profile struct {
	Name        string `yaml:"name"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Key         string `yaml:"key"`
	Fingerprint string `yaml:"fingerprint"`
	Mode        string `yaml:"mode"` // shell | socks5 | custom
	Exec        string `yaml:"exec"`
	Args        string `yaml:"args"`
}

type clientConf struct {
	Default string    `yaml:"default"`
	Targets []profile `yaml:"targets"`
}

func loadClientConf(path string) *clientConf {
	if path == "" {
		path = "client.conf"
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c clientConf
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil
	}
	return &c
}

func findProfile(name string, conf *clientConf) (profile, bool) {
	if conf == nil || name == "" {
		return profile{}, false
	}
	if _, _, err := net.SplitHostPort(name); err == nil {
		return profile{}, false // host:port 形式走直连
	}
	for _, p := range conf.Targets {
		if p.Name == name {
			if p.Mode == "" {
				p.Mode = "shell"
			}
			return p, true
		}
	}
	return profile{}, false
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	os.Exit(1)
}
