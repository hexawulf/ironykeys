package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hexawulf/ironykeys/internal/volume"
)

func TestCheckPasswordFD(t *testing.T) {
	// A pipe is what a caller hands over.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if err := checkPasswordFD(int(r.Fd())); err != nil {
		t.Errorf("pipe rejected: %v", err)
	}
	// An ordinary file is fine too (shell here-strings use one).
	f, err := os.CreateTemp(t.TempDir(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := checkPasswordFD(int(f.Fd())); err != nil {
		t.Errorf("regular file rejected: %v", err)
	}
	// Kernel files are what a reused descriptor points at under sudo.
	for _, p := range []string{"/proc/self/status", "/sys/kernel/mm/transparent_hugepage/enabled"} {
		k, err := os.Open(p)
		if err != nil {
			continue
		}
		if err := checkPasswordFD(int(k.Fd())); err == nil {
			t.Errorf("%s accepted as a password source", p)
		}
		_ = k.Close()
	}
	// Devices and closed descriptors.
	if n, err := os.Open("/dev/null"); err == nil {
		if err := checkPasswordFD(int(n.Fd())); err == nil {
			t.Error("/dev/null accepted")
		}
		_ = n.Close()
	}
	if err := checkPasswordFD(987654); err == nil {
		t.Error("closed descriptor accepted")
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]int64{"4096K": 4 << 20, "256M": 256 << 20, "1G": 1 << 30, "8388608": 8 << 20, "16m": 16 << 20}
	for in, want := range good {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "M", "-1M", "0", "1.5G", "lots", "99999999999G", "1T"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}

func runWithFD(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	fullArgs := append(append([]string(nil), args...), "--password-fd", fmt.Sprint(r.Fd()))
	rc := run(fullArgs, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestPasswdAndHeaderRestoreCLI(t *testing.T) {
	vault := filepath.Join(t.TempDir(), "cli.vc")
	if rc, _, errStr := runWithFD(t, "pass1\n", "create", vault, "--size", "4M", "--fs", "none", "--pim", "1"); rc != exitOK {
		t.Fatalf("create rc=%d err=%s", rc, errStr)
	}

	// Wrong old password in passwd must fail with exitNoMatch (3).
	if rc, _, _ := runWithFD(t, "wrong\npass2\n", "passwd", vault, "--pim", "1"); rc != exitNoMatch {
		t.Errorf("passwd wrong old password rc=%d, want %d", rc, exitNoMatch)
	}

	// Dry-run passwd changes nothing.
	if rc, out, errStr := runWithFD(t, "pass1\npass2\n", "passwd", vault, "--pim", "1", "--new-pim", "2", "--dry-run"); rc != exitOK || !strings.Contains(out, "Dry run") {
		t.Fatalf("passwd dry-run rc=%d out=%q err=%q", rc, out, errStr)
	}
	if rc, _, _ := runWithFD(t, "pass1\n", "verify", vault, "--pim", "1"); rc != exitOK {
		t.Errorf("verify with pass1 after dry-run rc=%d, want 0", rc)
	}

	// Real passwd changes password and PIM.
	if rc, _, errStr := runWithFD(t, "pass1\npass2\n", "passwd", vault, "--pim", "1", "--new-pim", "2"); rc != exitOK {
		t.Fatalf("passwd rc=%d err=%s", rc, errStr)
	}
	if rc, _, _ := runWithFD(t, "pass1\n", "verify", vault, "--pim", "1"); rc != exitNoMatch {
		t.Errorf("old password still accepted: rc=%d", rc)
	}
	if rc, _, errStr := runWithFD(t, "pass2\n", "verify", vault, "--pim", "2"); rc != exitOK {
		t.Fatalf("new password rejected: rc=%d err=%s", rc, errStr)
	}

	// header-restore when both headers are OK is a no-op (exit 0).
	if rc, out, _ := runWithFD(t, "pass2\n", "header-restore", vault, "--pim", "2"); rc != exitOK || !strings.Contains(out, "already OK") {
		t.Errorf("header-restore on healthy vault: rc=%d out=%q", rc, out)
	}

	// Damage primary header -> verify exits 6 -> header-restore repairs it -> verify exits 0.
	f, err := os.OpenFile(vault, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, 512), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if rc, _, _ := runWithFD(t, "pass2\n", "verify", vault, "--pim", "2"); rc != exitOneHeaderOK {
		t.Fatalf("verify with damaged primary: rc=%d, want %d", rc, exitOneHeaderOK)
	}
	if rc, _, errStr := runWithFD(t, "pass2\n", "header-restore", vault, "--pim", "2"); rc != exitOK {
		t.Fatalf("header-restore primary: rc=%d err=%s", rc, errStr)
	}
	if rc, _, _ := runWithFD(t, "pass2\n", "verify", vault, "--pim", "2"); rc != exitOK {
		t.Fatalf("verify after primary restore: rc=%d, want 0", rc)
	}

	// Damage backup header -> header-restore repairs it -> verify exits 0.
	f, err = os.OpenFile(vault, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, 512), 4<<20-volume.DataOffset); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if rc, _, errStr := runWithFD(t, "pass2\n", "header-restore", vault, "--pim", "2"); rc != exitOK {
		t.Fatalf("header-restore backup: rc=%d err=%s", rc, errStr)
	}
	if rc, _, _ := runWithFD(t, "pass2\n", "verify", vault, "--pim", "2"); rc != exitOK {
		t.Fatalf("verify after backup restore: rc=%d, want 0", rc)
	}
}
