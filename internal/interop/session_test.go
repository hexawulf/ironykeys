//go:build interop

package interop

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hexawulf/ironykeys/internal/session"
	"github.com/hexawulf/ironykeys/internal/volume"
)

const fsSize = 16 << 20

// newVault creates and formats a vault with IronyKeys.
func newVault(t *testing.T, fs string, pim int) string {
	t.Helper()
	session.StateDir = t.TempDir()
	vault := filepath.Join(t.TempDir(), "ikt.vc")
	if err := volume.Create(vault, fsSize, []byte(pass), pim); err != nil {
		t.Fatal(err)
	}
	if fs != "" {
		r, err := volume.Verify(vault, []byte(pass), pim)
		if err != nil || r.Usable() == nil {
			t.Fatalf("verify: %v", err)
		}
		if err := session.Format(vault, r.Usable(), r.Layout, fs, session.Owner{}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		session.Close("ikt")
		exec.Command("veracrypt", "--text", "--non-interactive", "-d", vault).Run()
		exec.Command("cryptsetup", "close", csName).Run()
		if loop, _ := session.LoopFor(vault); loop != "" {
			t.Errorf("loop device %s left attached to %s", loop, vault)
		}
	})
	return vault
}

func ikOpen(t *testing.T, vault string, pim int, mp string, ro bool) (*session.State, error) {
	t.Helper()
	r, err := volume.Verify(vault, []byte(pass), pim)
	if err != nil {
		t.Fatal(err)
	}
	h := r.Usable()
	if h == nil {
		t.Fatalf("no usable header: %v / %v", r.Primary.Err, r.Backup.Err)
	}
	return session.Open(session.OpenOptions{
		Vault: vault, Name: "ikt", Mountpoint: mp, ReadOnly: ro,
		Header: h, Layout: r.Layout, Owner: session.Owner{Home: t.TempDir()},
	})
}

func mustOpen(t *testing.T, vault string, pim int, mp string) *session.State {
	t.Helper()
	st, err := ikOpen(t, vault, pim, mp, false)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func mustClose(t *testing.T) {
	t.Helper()
	if _, err := session.Close("ikt"); err != nil {
		t.Fatal(err)
	}
}

func vcMount(t *testing.T, vault string, pim int, dir string) {
	run(t, "", "veracrypt", "--text", "--non-interactive",
		"--password="+pass, fmt.Sprintf("--pim=%d", pim), "--keyfiles=",
		"--protect-hidden=no", "--slot="+vcSlot, vault, dir)
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != want {
		t.Errorf("%s = %q, %v; want %q", path, b, err, want)
	}
}

// IronyKeys creates and formats; VeraCrypt and cryptsetup must agree.
func TestFormattedVaultMatrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, fs := range []string{"exfat", "ext4"} {
		for _, pim := range []int{0, 7} {
			t.Run(fmt.Sprintf("%s/pim=%d", fs, pim), func(t *testing.T) {
				vault := newVault(t, fs, pim)
				mp := filepath.Join(t.TempDir(), "mnt")

				st := mustOpen(t, vault, pim, mp)
				if st.FS != fs {
					t.Errorf("mounted as %s, want %s", st.FS, fs)
				}
				put(t, filepath.Join(mp, "from-ironykeys"), "written by ironykeys")
				mustClose(t)
				if _, err := os.Stat(mp); err == nil {
					t.Error("mountpoint created by open was not removed on close")
				}

				// The official VeraCrypt mounts the filesystem.
				vdir := t.TempDir()
				vcMount(t, vault, pim, vdir)
				expect(t, filepath.Join(vdir, "from-ironykeys"), "written by ironykeys")
				put(t, filepath.Join(vdir, "from-veracrypt"), "written by veracrypt")
				vcClose(t, vault)

				// cryptsetup sees the same filesystem type.
				dev := csOpen(t, vault, pim)
				if got := strings.TrimSpace(run(t, "", "blkid", "-o", "value", "-s", "TYPE", dev)); got != fs {
					t.Errorf("blkid via cryptsetup: %q, want %q", got, fs)
				}
				csClose(t)

				// Back in IronyKeys, both files are there.
				mustOpen(t, vault, pim, mp)
				expect(t, filepath.Join(mp, "from-ironykeys"), "written by ironykeys")
				expect(t, filepath.Join(mp, "from-veracrypt"), "written by veracrypt")
				mustClose(t)

				if fi, _ := os.Stat(vault); fi.Size() != fsSize {
					t.Errorf("vault size changed to %d", fi.Size())
				}
			})
		}
	}
}

// VeraCrypt creates and formats; IronyKeys must open it.
func TestVeraCryptMadeVaultOpens(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, fs := range []string{"exfat", "ext4"} {
		t.Run(fs, func(t *testing.T) {
			session.StateDir = t.TempDir()
			vault := filepath.Join(t.TempDir(), "ikt.vc")
			t.Cleanup(func() {
				session.Close("ikt")
				exec.Command("veracrypt", "--text", "--non-interactive", "-d", vault).Run()
			})
			run(t, "", "veracrypt", "--text", "--non-interactive", "--create", vault,
				"--size=16M", "--volume-type=normal", "--encryption=AES", "--hash=SHA-512",
				"--filesystem="+fs, "--pim=0", "--keyfiles=", "--password="+pass,
				"--random-source=/dev/urandom")
			vdir := t.TempDir()
			vcMount(t, vault, 0, vdir)
			put(t, filepath.Join(vdir, "from-veracrypt"), "veracrypt made this vault")
			vcClose(t, vault)

			mp := filepath.Join(t.TempDir(), "mnt")
			st := mustOpen(t, vault, 0, mp)
			if st.FS != fs {
				t.Errorf("mounted as %s, want %s", st.FS, fs)
			}
			expect(t, filepath.Join(mp, "from-veracrypt"), "veracrypt made this vault")
			put(t, filepath.Join(mp, "from-ironykeys"), "x")
			mustClose(t)
		})
	}
}

func TestOpenCloseFailures(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const pim = 7

	t.Run("second open is busy", func(t *testing.T) {
		vault := newVault(t, "exfat", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		mustOpen(t, vault, pim, mp)
		if _, err := ikOpen(t, vault, pim, filepath.Join(t.TempDir(), "other"), false); !errors.Is(err, session.ErrBusy) {
			t.Errorf("second open: %v, want ErrBusy", err)
		}
		expectOpen(t, vault, true)
		mustClose(t)
		expectOpen(t, vault, false)
	})

	t.Run("close with a busy mountpoint changes nothing", func(t *testing.T) {
		vault := newVault(t, "exfat", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		mustOpen(t, vault, pim, mp)
		f, err := os.Create(filepath.Join(mp, "held-open"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.Close("ikt"); !errors.Is(err, session.ErrBusy) {
			t.Errorf("close while busy: %v, want ErrBusy", err)
		}
		expectOpen(t, vault, true)
		if _, err := f.WriteString("still writable"); err != nil {
			t.Errorf("vault unusable after failed close: %v", err)
		}
		f.Close()
		mustClose(t)
		expectOpen(t, vault, false)
	})

	t.Run("damaged primary header opens via backup", func(t *testing.T) {
		vault := newVault(t, "exfat", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		mustOpen(t, vault, pim, mp)
		put(t, filepath.Join(mp, "keep"), "survives header damage")
		mustClose(t)

		f, _ := os.OpenFile(vault, os.O_WRONLY, 0)
		f.WriteAt(make([]byte, 512), 0)
		f.Close()
		r, _ := volume.Verify(vault, []byte(pass), pim)
		if r.Primary.Err == nil || r.Backup.Err != nil {
			t.Fatalf("primary: %v, backup: %v", r.Primary.Err, r.Backup.Err)
		}
		mustOpen(t, vault, pim, mp)
		expect(t, filepath.Join(mp, "keep"), "survives header damage")
		mustClose(t)
	})

	t.Run("read-only refuses writes", func(t *testing.T) {
		vault := newVault(t, "ext4", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		if _, err := ikOpen(t, vault, pim, mp, true); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mp, "x"), []byte("x"), 0o600); err == nil {
			t.Error("write succeeded on a read-only vault")
		}
		mustClose(t)
	})

	t.Run("unformatted vault leaves nothing behind", func(t *testing.T) {
		vault := newVault(t, "", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		if _, err := ikOpen(t, vault, pim, mp, false); !errors.Is(err, session.ErrNoFS) {
			t.Errorf("open: %v, want ErrNoFS", err)
		}
		expectOpen(t, vault, false)
		if _, err := os.Stat(mp); err == nil {
			t.Error("mountpoint left behind")
		}
	})

	t.Run("non-empty mountpoint is refused", func(t *testing.T) {
		vault := newVault(t, "exfat", pim)
		mp := t.TempDir()
		put(t, filepath.Join(mp, "existing"), "do not hide me")
		if _, err := ikOpen(t, vault, pim, mp, false); err == nil {
			t.Error("mounted over a non-empty directory")
		}
		expectOpen(t, vault, false)
	})

	t.Run("passwd and header-restore preserve data across VeraCrypt and cryptsetup", func(t *testing.T) {
		vault := newVault(t, "exfat", pim)
		mp := filepath.Join(t.TempDir(), "mnt")
		mustOpen(t, vault, pim, mp)
		put(t, filepath.Join(mp, "secret"), "survives-passwd-and-repair")
		mustClose(t)

		// 1. Corrupt primary header, then repair via RepairHeader.
		f, _ := os.OpenFile(vault, os.O_WRONLY, 0)
		f.WriteAt(make([]byte, 512), 0)
		f.Close()
		rDamaged, _ := volume.Verify(vault, []byte(pass), pim)
		if err := volume.RepairHeader(vault, 0, rDamaged.Usable(), []byte(pass), pim); err != nil {
			t.Fatalf("RepairHeader: %v", err)
		}
		rDamaged.Wipe()

		// 2. Change password and PIM via RewriteHeaders; VeraCrypt must open under the new password/PIM.
		const newPass = "new-interop-password"
		const newPIM = 9
		rOK, _ := volume.Verify(vault, []byte(pass), pim)
		if err := volume.RewriteHeaders(vault, rOK.Usable(), []byte(newPass), newPIM); err != nil {
			t.Fatalf("RewriteHeaders: %v", err)
		}
		rOK.Wipe()

		vdir := t.TempDir()
		run(t, "", "veracrypt", "--text", "--non-interactive",
			"--password="+newPass, fmt.Sprintf("--pim=%d", newPIM), "--keyfiles=",
			"--protect-hidden=no", "--slot="+vcSlot, vault, vdir)
		expect(t, filepath.Join(vdir, "secret"), "survives-passwd-and-repair")
		vcClose(t, vault)
	})
}

func expectOpen(t *testing.T, vault string, want bool) {
	t.Helper()
	loop, _ := session.LoopFor(vault)
	_, merr := os.Stat("/dev/mapper/ironykeys-ikt")
	if got := loop != "" && merr == nil; got != want {
		t.Errorf("open = %v (loop %q, mapping err %v), want %v", got, loop, merr, want)
	}
	if !want && (loop != "" || merr == nil) {
		t.Errorf("leftovers: loop %q, mapping exists %v", loop, merr == nil)
	}
}
