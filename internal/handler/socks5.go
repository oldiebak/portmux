package handler

import (
	"context"
	"io"
	"log"
	"net"
	"time"
)

type SOCKS5Handler struct {
	idle time.Duration
}

func init() {
	Register("socks5", func(args map[string]string) (Handler, error) {
		return &SOCKS5Handler{}, nil
	})
}

func (h *SOCKS5Handler) Name() string { return "socks5" }

func (h *SOCKS5Handler) SetIdleTimeout(d time.Duration) { h.idle = d }

func (h *SOCKS5Handler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn = newIdleConn(conn, h.idle)

	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("socks5: greeting read: %v", err)
		return err
	}
	if buf[0] != 0x05 {
		return nil
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("socks5: greeting methods: %v", err)
		return err
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		log.Printf("socks5: greeting reply: %v", err)
		return err
	}
	log.Printf("socks5: greeting ok (methods=%d)", nmethods)

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return nil
	}

	var targetAddr string
	switch req[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		targetAddr = net.IP(addr).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return err
		}
		targetAddr = string(name)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		targetAddr = net.IP(addr).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])

	target, err := net.Dial("tcp", net.JoinHostPort(targetAddr, itoa(targetPort)))
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer target.Close()
	target = newIdleConn(target, h.idle)

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(target, conn); errCh <- err }()
	go func() { _, err := io.Copy(conn, target); errCh <- err }()
	for i := 0; i < 2; i++ {
		<-errCh
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 6)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
