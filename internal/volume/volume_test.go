package volume

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/xts"

	"github.com/hexawulf/ironykeys/internal/header"
)

// The fixture was created by VeraCrypt 1.26.31; see SPEC.md section 3.2.
const (
	fixture     = "../../testdata/ref-aes-sha512.vc"
	fixturePass = "ironykeys-test-vector"
)

func copyFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "v.vc")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func overwrite(t *testing.T, path string, off int64, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	junk := make([]byte, n)
	rand.Read(junk)
	if _, err := f.WriteAt(junk, off); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFixture(t *testing.T) {
	r, err := Verify(fixture, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Primary.Err != nil || r.Backup.Err != nil {
		t.Fatalf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
	}
	h := r.Primary.Header
	if h.Version != 5 || h.MinProgVersion != 0x010B || h.VolumeSize != 3932160 ||
		h.MKScopeOffset != 131072 || h.EncAreaSize != 3932160 || h.SectorSize != 512 ||
		h.Flags != 0 || h.HiddenSize != 0 {
		t.Errorf("unexpected fields: %+v", h)
	}
	if r.Layout.DataSectors != 7680 {
		t.Errorf("data sectors = %d, want 7680", r.Layout.DataSectors)
	}

	// The master key must decrypt the known plaintext in the data area,
	// with the tweak counted from the start of the file (sector 256).
	c, err := xts.NewCipher(aes.NewCipher, h.MasterKey[:])
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(fixture)
	defer func() { _ = f.Close() }()
	ct := make([]byte, 1024)
	if _, err := f.ReadAt(ct, DataOffset); err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, 1024)
	c.Decrypt(pt[:512], ct[:512], 256)
	c.Decrypt(pt[512:], ct[512:], 257)
	want := append(bytes.Repeat([]byte("IRONYKEYS-M0-PLAINTEXT-SECTOR-0!"), 16), make([]byte, 512)...)
	if !bytes.Equal(pt, want) {
		t.Errorf("data area plaintext mismatch: %q...", pt[:32])
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	r, err := Verify(fixture, []byte("not-the-password"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Primary.Err, header.ErrNoMatch) || !errors.Is(r.Backup.Err, header.ErrNoMatch) {
		t.Errorf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
	}
	if r.Usable() != nil {
		t.Error("Usable() returned a header for a wrong password")
	}
}

func TestVerifyWrongPIM(t *testing.T) {
	r, err := Verify(fixture, []byte(fixturePass), 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Usable() != nil {
		t.Error("wrong PIM accepted")
	}
}

func TestVerifyDamagedPrimary(t *testing.T) {
	p := copyFixture(t)
	overwrite(t, p, 0, 512)
	r, err := Verify(p, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Primary.Err == nil || r.Backup.Err != nil {
		t.Fatalf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
	}
	if r.Usable() != r.Backup.Header {
		t.Error("Usable() did not fall back to the backup header")
	}
}

func TestVerifyDamagedBackup(t *testing.T) {
	p := copyFixture(t)
	overwrite(t, p, 4194304-131072, 512)
	r, err := Verify(p, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Primary.Err != nil || r.Backup.Err == nil {
		t.Fatalf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
	}
}

func TestOpenFastPathAndFallback(t *testing.T) {
	// Healthy primary: Open must succeed without touching the backup header.
	r, err := Open(fixture, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Wipe()
	if r.Primary.Err != nil || r.Backup.Header != nil || r.Backup.Err != nil {
		t.Fatalf("Open primary: %v, backup: %+v", r.Primary.Err, r.Backup)
	}
	// Damaged primary: Open falls back to the backup header.
	p := copyFixture(t)
	overwrite(t, p, 0, 512)
	r2, err := Open(p, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Wipe()
	if r2.Primary.Err == nil || r2.Backup.Err != nil || r2.Usable() != r2.Backup.Header {
		t.Fatalf("Open fallback primary: %v, backup: %v", r2.Primary.Err, r2.Backup.Err)
	}
}

func TestVerifyResizedFile(t *testing.T) {
	// A valid header in a file of the wrong size is a profile mismatch.
	p := copyFixture(t)
	if err := os.Truncate(p, 8<<20); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(p, []byte(fixturePass), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Primary.Err, ErrProfile) {
		t.Errorf("primary: %v, want ErrProfile", r.Primary.Err)
	}
}

func TestLayoutRejects(t *testing.T) {
	for _, size := range []int64{0, 511, 1 << 20, 4<<20 + 1} {
		if _, err := CheckLayout(size); err == nil {
			t.Errorf("size %d accepted", size)
		}
	}
	if _, err := Stat(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
	if _, err := Verify(filepath.Join(t.TempDir(), "missing.vc"), []byte("x"), 0); err == nil {
		t.Error("missing file accepted")
	}
}
