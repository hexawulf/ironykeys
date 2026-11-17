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

// RewriteHeaders encrypts h under password and pim with a fresh random salt
// for each header, writes both headers to path (backup first, primary last),
// syncs the file and verifies that both headers decrypt back to h. The data
// area is untouched.
func RewriteHeaders(path string, h *header.Header, password []byte, pim int) error {
	return updateHeaders(path, h, password, pim, nil)
}

// RepairHeader rewrites the header at off (0 or l.BackupOff) from the good
// header h with a fresh random salt, syncs the file and verifies that both
// headers now decrypt back to h.
func RepairHeader(path string, off int64, h *header.Header, password []byte, pim int) error {
	return updateHeaders(path, h, password, pim, []int64{off})
}

func updateHeaders(path string, h *header.Header, password []byte, pim int, offsets []int64) error {
	if _, err := kdf.HeaderKey(password, make([]byte, kdf.SaltSize), 1); err != nil {
		return err
	}
	if _, err := kdf.Iterations(pim); err != nil {
		return err
	}
	f, l, err := openVault(path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := CheckProfile(h, l); err != nil {
		return err
	}
	if offsets == nil {
		offsets = []int64{l.BackupOff, 0}
	}
	for _, off := range offsets {
		if off != 0 && off != l.BackupOff {
			return fmt.Errorf("invalid header offset %d", off)
		}
		if err := writeHeader(f, off, h, password, pim); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	r, err := Verify(path, password, pim)
	if err != nil {
		return err
	}
	defer r.Wipe()
	if r.Primary.Err != nil || r.Backup.Err != nil || *r.Primary.Header != *h {
		return errors.New("the updated headers did not verify")
	}
	return nil
}
