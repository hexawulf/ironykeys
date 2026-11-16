// Package header reads and writes the 512-byte VeraCrypt volume header for
// the one profile IronyKeys supports: AES-256-XTS, normal volume.
// See SPEC.md section 3.2 for the field table.
package header

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"hash/crc32"

	"golang.org/x/crypto/xts"
)

const (
	// Size is the size of the header in bytes.
	Size = 512
	// SaltSize is the length of the unencrypted salt at the start.
	SaltSize = 64
	// KeySize is the length of the header key and of the master key.
	KeySize = 64

	// FormatVersion and MinProgramVersion are the values VeraCrypt 1.26
	// writes; IronyKeys writes the same.
	FormatVersion     = 5
	MinProgramVersion = 0x010B

	magic = "VERA"
)

var (
	// ErrNoMatch means the decrypted header has no VERA magic: the password
	// (or PIM) is wrong, or this is not a volume of the supported profile.
	// The cases cannot be told apart.
	ErrNoMatch = errors.New("wrong password or not a VeraCrypt volume")
	// ErrCorrupt means the magic matched but a checksum did not.
	ErrCorrupt = errors.New("header checksum mismatch")
)

// Header holds the decrypted header fields.
type Header struct {
	Version        uint16
	MinProgVersion uint16
	HiddenSize     uint64
	VolumeSize     uint64
	MKScopeOffset  uint64
	EncAreaSize    uint64
	Flags          uint32
	SectorSize     uint32
	MasterKey      [KeySize]byte
}

// Decrypt decrypts a raw 512-byte header with the header key and parses it.
func Decrypt(raw, headerKey []byte) (*Header, error) {
	if len(raw) != Size {
		return nil, errors.New("header must be 512 bytes")
	}
	c, err := newCipher(headerKey)
	if err != nil {
		return nil, err
	}
	p := make([]byte, Size)
	defer clear(p)
	copy(p, raw[:SaltSize])
	c.Decrypt(p[SaltSize:], raw[SaltSize:], 0)

	if string(p[64:68]) != magic {
		return nil, ErrNoMatch
	}
	if binary.BigEndian.Uint32(p[252:256]) != crc32.ChecksumIEEE(p[64:252]) ||
		binary.BigEndian.Uint32(p[72:76]) != crc32.ChecksumIEEE(p[256:512]) {
		return nil, ErrCorrupt
	}
	h := &Header{
		Version:        binary.BigEndian.Uint16(p[68:70]),
		MinProgVersion: binary.BigEndian.Uint16(p[70:72]),
		HiddenSize:     binary.BigEndian.Uint64(p[92:100]),
		VolumeSize:     binary.BigEndian.Uint64(p[100:108]),
		MKScopeOffset:  binary.BigEndian.Uint64(p[108:116]),
		EncAreaSize:    binary.BigEndian.Uint64(p[116:124]),
		Flags:          binary.BigEndian.Uint32(p[124:128]),
		SectorSize:     binary.BigEndian.Uint32(p[128:132]),
	}
	copy(h.MasterKey[:], p[256:320])
	return h, nil
}

// Encrypt builds the raw 512-byte header from the fields, the salt and the
// header key. Reserved areas and the unused key area are zero, as VeraCrypt
// writes them.
func (h *Header) Encrypt(salt, headerKey []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, errors.New("salt must be 64 bytes")
	}
	c, err := newCipher(headerKey)
	if err != nil {
		return nil, err
	}
	p := make([]byte, Size)
	defer clear(p)
	copy(p[64:68], magic)
	binary.BigEndian.PutUint16(p[68:70], h.Version)
	binary.BigEndian.PutUint16(p[70:72], h.MinProgVersion)
	binary.BigEndian.PutUint64(p[92:100], h.HiddenSize)
	binary.BigEndian.PutUint64(p[100:108], h.VolumeSize)
	binary.BigEndian.PutUint64(p[108:116], h.MKScopeOffset)
	binary.BigEndian.PutUint64(p[116:124], h.EncAreaSize)
	binary.BigEndian.PutUint32(p[124:128], h.Flags)
	binary.BigEndian.PutUint32(p[128:132], h.SectorSize)
	copy(p[256:320], h.MasterKey[:])
	binary.BigEndian.PutUint32(p[72:76], crc32.ChecksumIEEE(p[256:512]))
	binary.BigEndian.PutUint32(p[252:256], crc32.ChecksumIEEE(p[64:252]))

	raw := make([]byte, Size)
	copy(raw, salt)
	c.Encrypt(raw[SaltSize:], p[SaltSize:], 0)
	return raw, nil
}

// newCipher returns AES-256-XTS. The length check matters: the xts package
// would accept a 32-byte key and silently use AES-128.
func newCipher(key []byte) (*xts.Cipher, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 64 bytes")
	}
	return xts.NewCipher(aes.NewCipher, key)
}

// Wipe zeroes the master key.
func (h *Header) Wipe() { clear(h.MasterKey[:]) }
