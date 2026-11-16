package volume

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hexawulf/ironykeys/internal/header"
	"github.com/hexawulf/ironykeys/internal/kdf"
)

// CheckCreate reports whether a vault of the given size can be created at
// path: the size must be valid, the path must not exist, and the directory
// must have room. It changes nothing.
func CheckCreate(path string, size int64) (Layout, error) {
	l, err := CheckLayout(size)
	if err != nil {
		return Layout{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return Layout{}, fmt.Errorf("%s already exists; refusing to overwrite", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Layout{}, err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &st); err != nil {
		return Layout{}, err
	}
	if free := int64(st.Bavail) * int64(st.Bsize); free < size {
		return Layout{}, fmt.Errorf("not enough free space: need %d bytes, have %d", size, free)
	}
	return l, nil
}

// Create writes a new vault of exactly size bytes at path. The whole file is
// filled with random bytes first and the two headers are written last, so an
// interrupted run leaves a file that does not verify. The data area holds no
// filesystem. Create never overwrites an existing file.
func Create(path string, size int64, password []byte, pim int) (err error) {
	l, err := CheckCreate(path, size)
	if err != nil {
		return err
	}
	// Derive nothing and create nothing if the password or PIM is unusable.
	if _, err := kdf.HeaderKey(password, make([]byte, kdf.SaltSize), 1); err != nil {
		return err
	}
	if _, err := kdf.Iterations(pim); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// O_EXCL guarantees this run created the file, so removing it on
	// failure cannot destroy anything that existed before.
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
	}()

	if _, err = io.CopyN(f, rand.Reader, size); err != nil {
		return fmt.Errorf("filling vault with random data: %w", err)
	}

	h := &header.Header{
		Version:        header.FormatVersion,
		MinProgVersion: header.MinProgramVersion,
		VolumeSize:     uint64(l.DataSize),
		MKScopeOffset:  DataOffset,
		EncAreaSize:    uint64(l.DataSize),
		SectorSize:     SectorSize,
	}
	defer h.Wipe()
	// VeraCrypt rejects an XTS key whose two halves are equal.
	for {
		if _, err = rand.Read(h.MasterKey[:]); err != nil {
			return err
		}
		if !bytes.Equal(h.MasterKey[:32], h.MasterKey[32:]) {
			break
		}
	}

	// Backup first, primary last: the vault only becomes openable by the
	// primary header once everything else is in place.
	for _, off := range []int64{l.BackupOff, 0} {
		if err = writeHeader(f, off, h, password, pim); err != nil {
			return err
		}
	}
	return f.Sync()
}

func writeHeader(f io.WriterAt, off int64, h *header.Header, password []byte, pim int) error {
	salt := make([]byte, kdf.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := kdf.HeaderKey(password, salt, pim)
	if err != nil {
		return err
	}
	defer clear(key)
	raw, err := h.Encrypt(salt, key)
	if err != nil {
		return err
	}
	_, err = f.WriteAt(raw, off)
	return err
}
