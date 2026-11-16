// Package kdf derives VeraCrypt header keys with PBKDF2-HMAC-SHA512.
package kdf

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"errors"
)

const (
	// SaltSize is the size of the header salt in bytes.
	SaltSize = 64
	// KeySize is the size of the derived header key: two 256-bit XTS keys.
	KeySize = 64
	// MaxPasswordLen is the longest password VeraCrypt accepts, in bytes.
	MaxPasswordLen = 128

	defaultIterations = 500000
)

// Iterations returns the PBKDF2 iteration count for a PIM. A PIM of 0 means
// "default". This is the rule for non-system volumes using SHA-512.
func Iterations(pim int) (int, error) {
	if pim < 0 {
		return 0, errors.New("PIM must not be negative")
	}
	if pim == 0 {
		return defaultIterations, nil
	}
	return 15000 + pim*1000, nil
}

// HeaderKey derives the 64-byte header key from a password and salt.
func HeaderKey(password, salt []byte, pim int) ([]byte, error) {
	if len(password) == 0 || len(password) > MaxPasswordLen {
		return nil, errors.New("password must be 1 to 128 bytes")
	}
	if len(salt) != SaltSize {
		return nil, errors.New("salt must be 64 bytes")
	}
	iters, err := Iterations(pim)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha512.New, string(password), salt, iters, KeySize)
}
