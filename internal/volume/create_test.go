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

func TestRewriteHeadersAndRepairHeader(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.vc")
	oldPW := []byte("initial-password")
	newPW := []byte("updated-password")
	if err := Create(p, MinSize, oldPW, testPIM); err != nil {
		t.Fatal(err)
	}
	r0, err := Verify(p, oldPW, testPIM)
	if err != nil || r0.Usable() == nil {
		t.Fatalf("initial verify: %v", err)
	}
	origMK := r0.Usable().MasterKey
	origFile, _ := os.ReadFile(p)
	origData := append([]byte(nil), origFile[DataOffset:MinSize-DataOffset]...)

	// 1. Change password and PIM via RewriteHeaders; data area and master key must not change.
	const newPIM = 2
	if err := RewriteHeaders(p, r0.Usable(), newPW, newPIM); err != nil {
		t.Fatalf("RewriteHeaders: %v", err)
	}
	r0.Wipe()

	if rOld, _ := Verify(p, oldPW, testPIM); rOld.Usable() != nil {
		t.Error("old password still accepted after RewriteHeaders")
	}
	r1, err := Verify(p, newPW, newPIM)
	if err != nil || r1.Primary.Err != nil || r1.Backup.Err != nil {
		t.Fatalf("verify after RewriteHeaders: %v / %+v", err, r1)
	}
	if r1.Primary.Header.MasterKey != origMK {
		t.Error("master key changed during RewriteHeaders")
	}
	afterFile, _ := os.ReadFile(p)
	if !bytes.Equal(afterFile[DataOffset:MinSize-DataOffset], origData) {
		t.Error("data area modified by RewriteHeaders")
	}
	if bytes.Equal(afterFile[:64], afterFile[MinSize-DataOffset:MinSize-DataOffset+64]) {
		t.Error("primary and backup share a salt after RewriteHeaders")
	}

	// 2. Corrupt primary header, then repair it from backup via RepairHeader.
	overwrite(t, p, 0, 512)
	rDamaged, _ := Verify(p, newPW, newPIM)
	if rDamaged.Primary.Err == nil || rDamaged.Backup.Err != nil {
		t.Fatalf("expected damaged primary, got: %+v", rDamaged)
	}
	if err := RepairHeader(p, 0, rDamaged.Usable(), newPW, newPIM); err != nil {
		t.Fatalf("RepairHeader primary: %v", err)
	}
	rDamaged.Wipe()
	rRepaired, _ := Verify(p, newPW, newPIM)
	if rRepaired.Primary.Err != nil || rRepaired.Backup.Err != nil {
		t.Fatalf("verify after primary repair: %+v", rRepaired)
	}
	rRepaired.Wipe()

	// 3. Corrupt backup header, then repair it from primary via RepairHeader.
	overwrite(t, p, r1.Layout.BackupOff, 512)
	if err := RepairHeader(p, r1.Layout.BackupOff, r1.Primary.Header, newPW, newPIM); err != nil {
		t.Fatalf("RepairHeader backup: %v", err)
	}
	r1.Wipe()
	rFinal, _ := Verify(p, newPW, newPIM)
	if rFinal.Primary.Err != nil || rFinal.Backup.Err != nil {
		t.Fatalf("verify after backup repair: %+v", rFinal)
	}
	rFinal.Wipe()
}
