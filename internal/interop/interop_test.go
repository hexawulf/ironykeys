//go:build interop

// Package interop checks IronyKeys vaults against the official VeraCrypt
// and cryptsetup. It needs root, loop devices and dm-crypt, so it is behind
// a build tag:
//
//	go test -c -tags interop -o interop.test ./internal/interop
//	sudo ./interop.test -test.v
package interop

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/xts"

	"github.com/hexawulf/ironykeys/internal/volume"
)

const (
	pass   = "interop-test-password"
	vcSlot = "61" // VeraCrypt slot, gives /dev/mapper/veracrypt61
	csName = "ik-interop"
)

func run(t *testing.T, stdin string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func pimArgs(pim int, flag string) []string {
	if pim == 0 {
		return nil
	}
	return []string{flag, fmt.Sprint(pim)}
}

func csOpen(t *testing.T, vault string, pim int) string {
	args := append([]string{"open", "--type", "tcrypt", "--veracrypt", "--key-file=-"}, pimArgs(pim, "--veracrypt-pim")...)
	run(t, pass, "cryptsetup", append(args, vault, csName)...)
	return "/dev/mapper/" + csName
}

func csClose(t *testing.T) { run(t, "", "cryptsetup", "close", csName) }

func vcOpen(t *testing.T, vault string, pim int) string {
	run(t, "", "veracrypt", "--text", "--non-interactive",
		"--password="+pass, fmt.Sprintf("--pim=%d", pim), "--keyfiles=",
		"--protect-hidden=no", "--filesystem=none", "--slot="+vcSlot, vault)
	return "/dev/mapper/veracrypt" + vcSlot
}

func vcClose(t *testing.T, vault string) {
	run(t, "", "veracrypt", "--text", "--non-interactive", "-d", vault)
}

func writeAt(t *testing.T, dev string, off int64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func readAt(t *testing.T, path string, off int64, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	return b
}

func devSize(t *testing.T, dev string) string {
	return strings.TrimSpace(run(t, "", "blockdev", "--getsize64", dev))
}

func TestCreatedVaultOpensElsewhere(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const size = 8 << 20
	dataSize := fmt.Sprint(size - volume.Overhead)

	for _, pim := range []int{0, 7} {
		t.Run(fmt.Sprintf("pim=%d", pim), func(t *testing.T) {
			vault := filepath.Join(t.TempDir(), "interop.vc")
			if err := volume.Create(vault, size, []byte(pass), pim); err != nil {
				t.Fatal(err)
			}
			// Best-effort teardown if a step below fails half way.
			t.Cleanup(func() {
				exec.Command("cryptsetup", "close", csName).Run()
				exec.Command("veracrypt", "--text", "--non-interactive", "-d", vault).Run()
			})

			// 1. cryptsetup reads the header and agrees on every field.
			dumpArgs := append([]string{"tcryptDump", "--veracrypt", "--key-file=-"}, pimArgs(pim, "--veracrypt-pim")...)
			dump := run(t, pass, "cryptsetup", append(dumpArgs, vault)...)
			for _, want := range []string{"VERACRYPT header", "Version:       \t5", "Driver req.:\t1.b",
				"Flags:       \t0x0", "Sector size:\t512", "MK offset:\t131072",
				"Volume size:\t" + dataSize, "PBKDF2 hash:\tsha512", "Cipher chain:\taes",
				"Cipher mode:\txts-plain64", "MK bits:       \t512"} {
				if !strings.Contains(dump, want) {
					t.Errorf("tcryptDump lacks %q:\n%s", want, dump)
				}
			}

			// 2. cryptsetup opens it; write a pattern into sector 0.
			a := bytes.Repeat([]byte("written-via-cryptsetup-mapping.."), 16)
			dev := csOpen(t, vault, pim)
			if got := devSize(t, dev); got != dataSize {
				t.Errorf("cryptsetup device size %s, want %s", got, dataSize)
			}
			writeAt(t, dev, 0, a)
			csClose(t)

			// 3. The official VeraCrypt opens it and reads the same bytes
			//    back; write a second pattern into sector 1.
			b := bytes.Repeat([]byte("written-via-veracrypt-mapping..."), 16)
			dev = vcOpen(t, vault, pim)
			if got := devSize(t, dev); got != dataSize {
				t.Errorf("veracrypt device size %s, want %s", got, dataSize)
			}
			if got := readAt(t, dev, 0, 512); !bytes.Equal(got, a) {
				t.Errorf("veracrypt read of sector 0: %q...", got[:32])
			}
			writeAt(t, dev, 512, b)
			vcClose(t, vault)

			// 4. cryptsetup sees what VeraCrypt wrote.
			dev = csOpen(t, vault, pim)
			if got := readAt(t, dev, 512, 512); !bytes.Equal(got, b) {
				t.Errorf("cryptsetup read of sector 1: %q...", got[:32])
			}
			csClose(t)

			// 5. IronyKeys still verifies both headers, and its master key
			//    decrypts both sectors straight from the file.
			r, err := volume.Verify(vault, []byte(pass), pim)
			if err != nil || r.Primary.Err != nil || r.Backup.Err != nil {
				t.Fatalf("verify after use: %v / %+v", err, r)
			}
			c, err := xts.NewCipher(aes.NewCipher, r.Primary.Header.MasterKey[:])
			if err != nil {
				t.Fatal(err)
			}
			ct := readAt(t, vault, volume.DataOffset, 1024)
			pt := make([]byte, 1024)
			c.Decrypt(pt[:512], ct[:512], 256)
			c.Decrypt(pt[512:], ct[512:], 257)
			if !bytes.Equal(pt[:512], a) || !bytes.Equal(pt[512:], b) {
				t.Error("own decryption of the data area does not match")
			}
			if fi, _ := os.Stat(vault); fi.Size() != size {
				t.Errorf("file size changed to %d", fi.Size())
			}
		})
	}
}
