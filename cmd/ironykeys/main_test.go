package main

import (
	"os"
	"testing"
)

func TestCheckPasswordFD(t *testing.T) {
	// A pipe is what a caller hands over.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := checkPasswordFD(int(r.Fd())); err != nil {
		t.Errorf("pipe rejected: %v", err)
	}
	// An ordinary file is fine too (shell here-strings use one).
	f, err := os.CreateTemp(t.TempDir(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
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
		k.Close()
	}
	// Devices and closed descriptors.
	if n, err := os.Open("/dev/null"); err == nil {
		if err := checkPasswordFD(int(n.Fd())); err == nil {
			t.Error("/dev/null accepted")
		}
		n.Close()
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
