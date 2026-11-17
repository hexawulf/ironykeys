package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNameAndNameFor(t *testing.T) {
	for _, good := range []string{"a", "IronyKeys", "vault_1-2"} {
		if err := CheckName(good); err != nil {
			t.Errorf("CheckName(%q) = %v", good, err)
		}
	}
	for _, bad := range []string{"", "-lead", "_lead", "../etc", "a/b", "a b"} {
		if err := CheckName(bad); err == nil {
			t.Errorf("CheckName(%q) accepted", bad)
		}
	}
	if got, err := NameFor("/home/you/vaults/IronyKeys.vc"); err != nil || got != "IronyKeys" {
		t.Errorf("NameFor = %q, %v", got, err)
	}
	if _, err := NameFor("/home/you/vaults/.vc"); err == nil {
		t.Error("NameFor accepted empty base")
	}
}

func TestUnescape(t *testing.T) {
	if got := unescape(`/mnt/my\040vault\134dir`); got != `/mnt/my vault\dir` {
		t.Errorf("unescape = %q", got)
	}
	if got := unescape(`/mnt/plain`); got != `/mnt/plain` {
		t.Errorf("unescape plain = %q", got)
	}
}

func TestListRejectsInvalidName(t *testing.T) {
	old := StateDir
	StateDir = t.TempDir()
	defer func() { StateDir = old }()

	st := &State{Name: "valid_vault", Vault: "/tmp/v.vc", Mapping: "ironykeys-valid_vault", Mountpoint: "/tmp/m"}
	if err := writeState(st); err != nil {
		t.Fatal(err)
	}
	got, err := List()
	if err != nil || len(got) != 1 || got[0].Name != "valid_vault" {
		t.Fatalf("List() = %+v, %v", got, err)
	}

	// A tampered state file with a path-traversal Name must be rejected.
	bad := filepath.Join(StateDir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"name":"../escape","vault":"/tmp/v.vc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := List(); err == nil {
		t.Error("List() accepted invalid state name")
	}
}

func TestPrepareMountpointRejectsFileAncestor(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var undo []func()
	if _, err := prepareMountpoint(filepath.Join(file, "sub", "mnt"), Owner{UID: os.Getuid(), GID: os.Getgid()}, &undo); err == nil {
		t.Error("prepareMountpoint accepted file ancestor")
	}
}
