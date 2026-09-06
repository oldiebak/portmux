package handler

import (
	"context"
	"io"
	"net"
	"time"
)

type TCPProxyHandler struct {
	Target string
	idle   time.Duration
}

func init() {
	Register("tcp_proxy", func(args map[string]string) (Handler, error) {
		target := args["target"]
		if target == "" {
			target = "127.0.0.1:80"
		}
		return &TCPProxyHandler{Target: target}, nil
	})
}

func (h *TCPProxyHandler) Name() string { return "tcp_proxy" }

// KeepFingerprint: "GET " 等指纹是真实 HTTP 数据前缀, 解密后需拼回
func (h *TCPProxyHandler) KeepFingerprint() {}

func (h *TCPProxyHandler) SetIdleTimeout(d time.Duration) { h.idle = d }

func (h *TCPProxyHandler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn = newIdleConn(conn, h.idle)

	backend, err := net.Dial("tcp", h.Target)
	if err != nil {
		return err
	}
	defer backend.Close()
	backend = newIdleConn(backend, h.idle)

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, backend)
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		<-errCh
	}
	return nil
}
