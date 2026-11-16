package header

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func sample(t *testing.T) (*Header, []byte, []byte) {
	t.Helper()
	h := &Header{
		Version: FormatVersion, MinProgVersion: MinProgramVersion,
		VolumeSize: 3932160, MKScopeOffset: 131072, EncAreaSize: 3932160,
		SectorSize: 512,
	}
	salt := make([]byte, SaltSize)
	key := make([]byte, KeySize)
	rand.Read(h.MasterKey[:])
	rand.Read(salt)
	rand.Read(key)
	return h, salt, key
}

func TestRoundTrip(t *testing.T) {
	h, salt, key := sample(t)
	raw, err := h.Encrypt(salt, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != Size || !bytes.Equal(raw[:SaltSize], salt) {
		t.Fatal("bad raw header layout")
	}
	got, err := Decrypt(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *h {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, h)
	}
}

func TestWrongKey(t *testing.T) {
	h, salt, key := sample(t)
	raw, _ := h.Encrypt(salt, key)
	key[0] ^= 1
	if _, err := Decrypt(raw, key); !errors.Is(err, ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch", err)
	}
}

func TestCorruption(t *testing.T) {
	h, salt, key := sample(t)
	// Offsets chosen so the damaged AES block does not contain the magic.
	for _, off := range []int{100, 200, 300, 511} {
		raw, _ := h.Encrypt(salt, key)
		raw[off] ^= 0x80
		if _, err := Decrypt(raw, key); !errors.Is(err, ErrCorrupt) {
			t.Errorf("flip at %d: err = %v, want ErrCorrupt", off, err)
		}
	}
	raw, _ := h.Encrypt(salt, key)
	raw[65] ^= 0x80 // block holding the magic
	if _, err := Decrypt(raw, key); !errors.Is(err, ErrNoMatch) {
		t.Errorf("flip in magic block: err = %v, want ErrNoMatch", err)
	}
}

func TestBadLengths(t *testing.T) {
	h, salt, key := sample(t)
	if _, err := Decrypt(make([]byte, 511), key); err == nil {
		t.Error("short header accepted")
	}
	if _, err := h.Encrypt(salt[:8], key); err == nil {
		t.Error("short salt accepted")
	}
	if _, err := h.Encrypt(salt, key[:32]); err == nil {
		t.Error("short key accepted")
	}
}

func TestDecryptRejectsShortKey(t *testing.T) {
	h, salt, key := sample(t)
	raw, _ := h.Encrypt(salt, key)
	if _, err := Decrypt(raw, key[:32]); err == nil || errors.Is(err, ErrNoMatch) {
		t.Errorf("short key: err = %v, want a length error", err)
	}
}
