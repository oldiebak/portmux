package isn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type Magic struct {
	prefix uint16
}

func NewMagic(key string) *Magic {
	h := sha256.Sum256([]byte(key))
	return &Magic{prefix: binary.BigEndian.Uint16(h[:2])}
}

func (m *Magic) Encode() (uint32, error) {
	rand16, err := rand.Int(rand.Reader, big.NewInt(65536))
	if err != nil {
		return 0, err
	}
	isn := uint32(m.prefix)<<16 | uint32(rand16.Uint64())
	return isn, nil
}

func (m *Magic) Verify(isn uint32) bool {
	return uint16(isn>>16) == m.prefix
}
