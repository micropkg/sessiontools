package sessiontools

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/micropkg/sessiontools/type/connection"
	"golang.org/x/crypto/chacha20poly1305"
)

//Manager : The object that signs the session.
type Manager struct {
	key  []byte
	mode int
	c    connection.Connection
	aead cipher.AEAD
}

//NewManager : Create New Manager
func NewManager(key []byte, c connection.Connection) (*Manager, error) {
	//c.Open()
	m := new(Manager)
	m.c = c
	m.key = key
	m.mode = 1
	aead, err := chacha20poly1305.NewX(m.key)
	if err != nil {
		return nil, err
	}
	m.aead = aead
	return m, nil
}

func (m *Manager) seal(v []byte) []byte {
	nonce := make([]byte, m.aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ct := m.aead.Seal(nil, nonce, v, nil)
	r := make([]byte, len(ct)+m.aead.NonceSize())
	copy(r[:m.aead.NonceSize()], nonce)
	copy(r[m.aead.NonceSize():], ct)
	return r
}

func (m *Manager) open(v []byte) (r []byte, ok bool) {
	nonce := v[:m.aead.NonceSize()]
	r, err := m.aead.Open(nil, nonce, v[m.aead.NonceSize():], nil)
	if err != nil {
		return r, false
	}
	return r, true
}
