package cryptoio

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func pipePair(t *testing.T, key []byte) (*EncryptedConn, *EncryptedConn) {
	c1, c2 := net.Pipe()
	e1, err := New(c1, key)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := New(c2, key)
	if err != nil {
		t.Fatal(err)
	}
	return e1, e2
}

func TestRoundtripSmall(t *testing.T) {
	key := DeriveKey("test-key")
	a, b := pipePair(t, key)
	defer a.Close()
	defer b.Close()

	go func() {
		a.Write([]byte("hello encrypted world"))
		a.Close()
	}()
	n, err := io.ReadAll(b)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(n) != "hello encrypted world" {
		t.Fatalf("got %q", n)
	}
}

func TestRoundtripMultiChunk(t *testing.T) {
	key := DeriveKey("k2")
	a, b := pipePair(t, key)
	defer a.Close()
	defer b.Close()

	big := bytes.Repeat([]byte("A"), maxChunkPlain*3+1234)
	done := make(chan struct{})
	go func() {
		a.Write(big)
		a.Close()
		close(done)
	}()
	got, err := io.ReadAll(b)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("mismatch: %d vs %d", len(got), len(big))
	}
	<-done
}

func TestPartialReads(t *testing.T) {
	key := DeriveKey("k3")
	a, b := pipePair(t, key)
	defer a.Close()
	defer b.Close()

	go func() {
		a.Write([]byte("partial-read-test-data"))
		time.Sleep(50 * time.Millisecond)
		a.Close()
	}()
	var out []byte
	tmp := make([]byte, 3) // 小缓冲强制多次 Read
	for {
		n, err := b.Read(tmp)
		out = append(out, tmp[:n]...)
		if err == io.EOF || (err == io.ErrClosedPipe && n == 0) {
			break
		}
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
	}
	if string(out) != "partial-read-test-data" {
		t.Fatalf("got %q", out)
	}
}

func TestWrongKeyFails(t *testing.T) {
	c1, c2 := net.Pipe()
	e1, _ := New(c1, DeriveKey("aaa"))
	e2, _ := New(c2, DeriveKey("bbb"))
	defer e1.Close()
	defer e2.Close()

	go func() {
		e1.Write([]byte("secret"))
		e1.Close()
	}()
	_, err := io.ReadAll(e2)
	if err == nil {
		t.Fatal("wrong key should fail to decrypt")
	}
}
