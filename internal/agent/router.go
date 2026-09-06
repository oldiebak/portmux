package agent

import (
	"bytes"
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"portmux/internal/cryptoio"
	"portmux/internal/handler"
)

type MatchType int

const (
	MatchPrefix   MatchType = iota
	MatchWildcard
)

type Router struct {
	rules         []*handler.Rule
	cryptoEnabled bool
	cryptoKey     []byte
	peekTimeout   time.Duration
	idleTimeout   time.Duration
	maxFpLen      int
}

func NewRouter(cfg *Config) *Router {
	r := &Router{
		cryptoEnabled: cfg.Crypto.Enabled,
		cryptoKey:     cryptoio.DeriveKey(cfg.MagicKey),
		peekTimeout:   time.Duration(cfg.Timeouts.PeekSeconds) * time.Second,
		idleTimeout:   time.Duration(cfg.Timeouts.IdleSeconds) * time.Second,
	}
	if r.peekTimeout <= 0 {
		r.peekTimeout = 3 * time.Second
	}
	for _, rc := range cfg.Rules {
		h, err := handler.Create(rc.Handler, rc.HandlerArgs)
		if err != nil || h == nil {
			continue
		}
		// fingerprint 为空时回退到 fingerprint_raw (hex 转义形式)
		fpStr := rc.Fingerprint
		if fpStr == "" {
			fpStr = rc.FingerprintRaw
		}
		fp, typ := parseFingerprint(fpStr)
		var fpBytes []byte
		if typ == MatchPrefix {
			fpBytes = fp
		}
		rule := &handler.Rule{
			Name:        rc.Name,
			Fingerprint: fpBytes,
			Handler:     h,
			Priority:    rc.Priority,
		}
		if len(fpBytes) > r.maxFpLen {
			r.maxFpLen = len(fpBytes)
		}
		// 代理类 handler 设置空闲超时
		if s, ok := h.(handler.IdleSetter); ok {
			s.SetIdleTimeout(r.idleTimeout)
		}
		r.rules = append(r.rules, rule)
	}
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].Priority < r.rules[j].Priority
	})
	return r
}

func (r *Router) Route(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// peek: 循环读取直到覆盖最长指纹长度 (慢客户端分包也能匹配), 带超时
	var peeked []byte
	if r.maxFpLen > 0 {
		conn.SetReadDeadline(time.Now().Add(r.peekTimeout))
		buf := make([]byte, 64)
		for len(peeked) < r.maxFpLen {
			n, err := conn.Read(buf)
			if n > 0 {
				peeked = append(peeked, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		conn.SetReadDeadline(time.Time{})
		if len(peeked) == 0 {
			return
		}
	}

	for _, rule := range r.rules {
		if rule.Fingerprint == nil {
			log.Printf("router: wildcard rule %q", rule.Name)
			r.dispatch(ctx, rule, conn, peeked, 0)
			return
		}
		if bytes.HasPrefix(peeked, rule.Fingerprint) {
			log.Printf("router: rule %q matched", rule.Name)
			r.dispatch(ctx, rule, conn, peeked, len(rule.Fingerprint))
			return
		}
	}
	log.Printf("router: no rule matched, closing")
}

// dispatch 按规则分发: 加密模式下明文指纹只用于路由, 之后的数据流是密文。
//   - 丢弃型 handler (shell/socks5 等): 指纹是纯路由数据, 直接丢弃;
//   - 保留型 handler (tcp_proxy/sliver, 实现 FingerprintKeeper): 指纹是业务数据前缀,
//     解密后拼回流首。
func (r *Router) dispatch(ctx context.Context, rule *handler.Rule, conn net.Conn, peeked []byte, fpLen int) {
	if len(peeked) > 12 {
		log.Printf("router: dispatch %s peeked=%d fpLen=%d head=% x", rule.Name, len(peeked), fpLen, peeked[:12])
	} else {
		log.Printf("router: dispatch %s peeked=%d fpLen=%d head=% x", rule.Name, len(peeked), fpLen, peeked)
	}
	pc := newPeekedConn(conn, peeked)
	if r.cryptoEnabled {
		pc.Consume(fpLen)
		ec, err := cryptoio.New(pc, r.cryptoKey)
		if err != nil {
			log.Printf("router: crypto init: %v", err)
			return
		}
		var out net.Conn = ec
		if _, keep := rule.Handler.(handler.FingerprintKeeper); keep && fpLen > 0 {
			out = newPrependConn(peeked[:fpLen], ec)
		}
		rule.Handler.Handle(ctx, out)
		return
	}
	rule.Handler.Handle(ctx, pc)
}

func parseFingerprint(fp string) ([]byte, MatchType) {
	if fp == "*" || fp == "" {
		return nil, MatchWildcard
	}
	if strings.HasPrefix(fp, "\\x") || strings.Contains(fp, "\\x") {
		return parseHexFingerprint(fp), MatchPrefix
	}
	return []byte(fp), MatchPrefix
}

func parseHexFingerprint(fp string) []byte {
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

// peekedConn 回放已 peek 的字节; Consume 丢弃前 n 字节 (指纹), 余下交给上层。
type peekedConn struct {
	net.Conn
	buf []byte
	off int
}

func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
	buf := make([]byte, len(peeked))
	copy(buf, peeked)
	return &peekedConn{Conn: conn, buf: buf}
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(b, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *peekedConn) Consume(n int) {
	if n > len(c.buf)-c.off {
		n = len(c.buf) - c.off
	}
	c.off += n
}

// prependConn 在流首拼接明文前缀 (tcp_proxy 的指纹回填)
type prependConn struct {
	net.Conn
	prefix []byte
	off    int
}

func newPrependConn(prefix []byte, conn net.Conn) *prependConn {
	return &prependConn{Conn: conn, prefix: prefix}
}

func (c *prependConn) Read(b []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(b, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}
