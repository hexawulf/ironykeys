package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// PIM 1 keeps key derivation fast in tests (16,000 iterations).
const testPIM = 1

func TestCreateThenVerify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new.vc")
	pw := []byte("create-test-password")
	if err := Create(p, MinSize, pw, testPIM); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != MinSize {
		t.Errorf("size = %d, want %d", fi.Size(), MinSize)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	r, err := Verify(p, pw, testPIM)
	if err != nil {
		t.Fatal(err)
	}
	if r.Primary.Err != nil || r.Backup.Err != nil {
		t.Fatalf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
	}
	if r2, _ := Verify(p, []byte("other"), testPIM); r2.Usable() != nil {
		t.Error("wrong password accepted")
	}
	if r3, _ := Verify(p, pw, testPIM+1); r3.Usable() != nil {
		t.Error("wrong PIM accepted")
	}

	b, _ := os.ReadFile(p)
	if bytes.Equal(b[:64], b[MinSize-DataOffset:MinSize-DataOffset+64]) {
		t.Error("primary and backup header share a salt")
	}
	// No run of zeros anywhere: every area outside the headers is random.
	if bytes.Contains(b, make([]byte, 64)) {
		t.Error("vault contains a 64-byte run of zeros")
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keep.vc")
	if err := os.WriteFile(p, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Create(p, MinSize, []byte("x"), testPIM); err == nil {
		t.Fatal("existing file overwritten")
	}
	if b, _ := os.ReadFile(p); string(b) != "precious" {
		t.Errorf("existing file changed: %q", b)
	}
	// A dangling symlink must not be followed either.
	link := filepath.Join(t.TempDir(), "link.vc")
	os.Symlink(filepath.Join(t.TempDir(), "target"), link)
	if err := Create(link, MinSize, []byte("x"), testPIM); err == nil {
		t.Error("created through a symlink")
	}
}

func TestCreateBadInputLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		size int64
		pw   []byte
		pim  int
	}{
		{"small", 1 << 20, []byte("x"), testPIM},
		{"unaligned", MinSize + 1, []byte("x"), testPIM},
		{"nopass", MinSize, nil, testPIM},
		{"longpass", MinSize, make([]byte, 129), testPIM},
		{"badpim", MinSize, []byte("x"), -1},
	}
	for _, c := range cases {
		p := filepath.Join(dir, c.name+".vc")
		if err := Create(p, c.size, c.pw, c.pim); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s: file left behind", c.name)
		}
	}
	if err := Create(filepath.Join(dir, "nodir", "v.vc"), MinSize, []byte("x"), testPIM); err == nil {
		t.Error("created in a missing directory")
	}
}
