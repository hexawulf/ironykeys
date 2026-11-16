// Package volume knows the layout of a VeraCrypt file container and checks
// its headers. See SPEC.md section 3.
package volume

import (
	"errors"
	"fmt"
	"io"
	"os"

	"ironykeys/internal/header"
	"ironykeys/internal/kdf"
)

const (
	SectorSize     = 512
	HeaderAreaSize = 65536
	// DataOffset is where the data area starts: after the primary header
	// area and the (unused) hidden-volume header area.
	DataOffset = 2 * HeaderAreaSize
	// Overhead is the total space used by the four header areas.
	Overhead = 4 * HeaderAreaSize
	// MinSize is the smallest vault IronyKeys handles.
	MinSize = 4 << 20
)

// ErrProfile means the volume is valid VeraCrypt but outside the one profile
// IronyKeys supports.
var ErrProfile = errors.New("volume is outside the supported profile")

// Layout describes what can be known about a file without the password.
type Layout struct {
	Size        int64
	DataSize    int64
	DataSectors int64
	BackupOff   int64
}

// CheckLayout validates the size of a candidate vault file.
func CheckLayout(size int64) (Layout, error) {
	if size%SectorSize != 0 {
		return Layout{}, fmt.Errorf("size %d is not a multiple of %d", size, SectorSize)
	}
	if size < MinSize {
		return Layout{}, fmt.Errorf("size %d is below the %d-byte minimum", size, MinSize)
	}
	return Layout{
		Size:        size,
		DataSize:    size - Overhead,
		DataSectors: (size - Overhead) / SectorSize,
		BackupOff:   size - DataOffset,
	}, nil
}

// Stat returns the layout of the file at path. It refuses anything that is
// not a regular file.
func Stat(path string) (Layout, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Layout{}, err
	}
	if !fi.Mode().IsRegular() {
		return Layout{}, fmt.Errorf("%s is not a regular file", path)
	}
	return CheckLayout(fi.Size())
}

// CheckProfile compares decrypted header fields with the supported profile.
func CheckProfile(h *header.Header, l Layout) error {
	bad := func(what string, got, want any) error {
		return fmt.Errorf("%w: %s is %v, expected %v", ErrProfile, what, got, want)
	}
	switch {
	case h.Version != header.FormatVersion:
		return bad("header version", h.Version, header.FormatVersion)
	case h.HiddenSize != 0:
		return bad("hidden volume size", h.HiddenSize, 0)
	case h.Flags != 0:
		return bad("flags", h.Flags, 0)
	case h.SectorSize != SectorSize:
		return bad("sector size", h.SectorSize, SectorSize)
	case h.MKScopeOffset != DataOffset:
		return bad("master key scope offset", h.MKScopeOffset, DataOffset)
	case h.VolumeSize != uint64(l.DataSize):
		return bad("volume size", h.VolumeSize, l.DataSize)
	case h.EncAreaSize != uint64(l.DataSize):
		return bad("encrypted area size", h.EncAreaSize, l.DataSize)
	}
	return nil
}

// HeaderResult is the outcome of checking one header.
type HeaderResult struct {
	Header *header.Header // nil unless Err is nil
	Err    error
}

// Result is the outcome of checking both headers of a vault.
type Result struct {
	Layout  Layout
	Primary HeaderResult
	Backup  HeaderResult
}

// Usable returns the header to open the vault with: the primary if it is
// good, otherwise the backup. It returns nil if neither is good.
func (r *Result) Usable() *header.Header {
	if r.Primary.Err == nil {
		return r.Primary.Header
	}
	if r.Backup.Err == nil {
		return r.Backup.Header
	}
	return nil
}

// Wipe zeroes the master keys held in the result.
func (r *Result) Wipe() {
	for _, h := range []*header.Header{r.Primary.Header, r.Backup.Header} {
		if h != nil {
			h.Wipe()
		}
	}
}

// Verify checks the password against the primary and the backup header and
// checks each against the supported profile. It only reads the file. The
// returned error is for failures to read the file at all; per-header
// outcomes are in the Result.
func Verify(path string, password []byte, pim int) (*Result, error) {
	l, err := Stat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Re-check the size on the open file so the offsets below are safe even
	// if the file changed between Stat and Open.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if l, err = CheckLayout(fi.Size()); err != nil {
		return nil, err
	}

	r := &Result{Layout: l}
	if r.Primary, err = readHeader(f, 0, l, password, pim); err != nil {
		return nil, err
	}
	if r.Backup, err = readHeader(f, l.BackupOff, l, password, pim); err != nil {
		return nil, err
	}
	if r.Primary.Err == nil && r.Backup.Err == nil &&
		*r.Primary.Header != *r.Backup.Header {
		r.Backup.Header.Wipe()
		r.Backup = HeaderResult{Err: errors.New("backup header does not match the primary header")}
	}
	return r, nil
}

func readHeader(f io.ReaderAt, off int64, l Layout, password []byte, pim int) (HeaderResult, error) {
	raw := make([]byte, header.Size)
	if _, err := f.ReadAt(raw, off); err != nil {
		return HeaderResult{}, err
	}
	key, err := kdf.HeaderKey(password, raw[:header.SaltSize], pim)
	if err != nil {
		return HeaderResult{}, err
	}
	defer clear(key)
	h, err := header.Decrypt(raw, key)
	if err != nil {
		return HeaderResult{Err: err}, nil
	}
	if err := CheckProfile(h, l); err != nil {
		h.Wipe()
		return HeaderResult{Err: err}, nil
	}
	return HeaderResult{Header: h}, nil
}
