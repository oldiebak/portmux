// Package cryptoio 提供 chunked XChaCha20-Poly1305 流式加密封装。
//
// 线格式: [len u16 BE][nonce 24B][sealed(明文+16B tag)]
//   len = 密封后长度 (明文 + 16), 单块明文上限 32KB
// 密钥派生: DeriveKey(magicKey) = SHA256("portmux-stream-v1:" + magicKey)
package cryptoio

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	maxChunkPlain = 32 * 1024
	headerLen     = 2
)

// DeriveKey 从 magic_key 派生 32 字节流加密密钥 (agent 与 wrap 必须一致)
func DeriveKey(magicKey string) []byte {
	h := sha256.Sum256([]byte("portmux-stream-v1:" + magicKey))
	return h[:]
}

// EncryptedConn 对底层连接做分块 AEAD 加密。
// 并发写安全 (内部加锁), 读由调用方串行使用。
type EncryptedConn struct {
	net.Conn
	aead  interface {
		NonceSize() int
		Overhead() int
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	wmu     sync.Mutex
	rbuf    []byte // 已解密未消费的明文
	rbufOff int
}

func New(conn net.Conn, key []byte) (*EncryptedConn, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &EncryptedConn{Conn: conn, aead: aead}, nil
}

func (c *EncryptedConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunkPlain {
			n = maxChunkPlain
		}
		chunk := p[:n]
		nonce := make([]byte, c.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, err
		}
		sealed := c.aead.Seal(nil, nonce, chunk, nil)
		hdr := make([]byte, headerLen)
		// 帧长 = nonce + 密文(含tag), 读取端据此一次性取完整帧
		binary.BigEndian.PutUint16(hdr, uint16(c.aead.NonceSize()+len(sealed)))
		// 一次 Write 保证分块不被外部(如另一端 recv)截半解读
		if _, err := writeFull(c.Conn, append(append(hdr, nonce...), sealed...)); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *EncryptedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// 先消费解密缓冲
	if c.rbufOff < len(c.rbuf) {
		n := copy(p, c.rbuf[c.rbufOff:])
		c.rbufOff += n
		return n, nil
	}
	// 读一个完整块
	plain, err := c.readChunk()
	if err != nil {
		return 0, err
	}
	n := copy(p, plain)
	if n < len(plain) {
		c.rbuf = plain
		c.rbufOff = n
	}
	return n, nil
}

func (c *EncryptedConn) readChunk() ([]byte, error) {
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(c.Conn, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr))
	if length < c.aead.NonceSize()+c.aead.Overhead() {
		return nil, errors.New("cryptoio: bad chunk length")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}
	nonce := buf[:c.aead.NonceSize()]
	sealed := buf[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, errors.New("cryptoio: decrypt failed (密钥不一致或数据损坏)")
	}
	return plain, nil
}

func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		total += n
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

// 保证接口满足 net.Conn (Read/Write 已实现, 其余继承底层)
var _ net.Conn = (*EncryptedConn)(nil)

// 与 deadlineConn 协同: 转发底层超时设置
func (c *EncryptedConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *EncryptedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
func (c *EncryptedConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
