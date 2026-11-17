// Command ironykeys creates and opens fixed-size encrypted vault files in
// the VeraCrypt format. See SPEC.md.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/hexawulf/ironykeys/internal/header"
	"github.com/hexawulf/ironykeys/internal/kdf"
	"github.com/hexawulf/ironykeys/internal/session"
	"github.com/hexawulf/ironykeys/internal/volume"
)

var version = "0.1.0"

// Exit codes, SPEC.md section 4.2.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitNoMatch     = 3
	exitBusy        = 4
	exitProfile     = 5
	exitOneHeaderOK = 6
)

const usage = `Usage:
  ironykeys create <vault> [--size 256M] [--fs exfat|ext4|none] [--pim N] [--dry-run]
  ironykeys open   <vault> [<mountpoint>] [--read-only] [--name NAME] [--pim N]
  ironykeys close  <vault|name>
  ironykeys status [<vault|name>] [--quiet]
  ironykeys verify <vault> [--pim N]
  ironykeys info   <vault>
  ironykeys version

create  Write a new fixed-size vault and format it. Never overwrites a file.
open    Unlock a vault and mount it (default: ~/IronyKeys/<name>).
close   Unmount and lock an open vault.
status  List open vaults, or say whether one is open.
        With --quiet: no output, exit 4 if open, 0 if closed.
verify  Check the password against both headers. Never mounts.
info    Show what is knowable without the password.

create, open and verify ask for the password on the terminal, or read it
with --password-fd N. Under sudo only descriptor 0 survives, so use
--password-fd 0 there. Sizes take a K, M or G suffix (powers of 1024).
open, close and formatting need root: run them with sudo.
`

func main() {
	_ = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	switch args[0] {
	case "create":
		return cmdCreate(args[1:], out, errw)
	case "verify":
		return cmdVerify(args[1:], out, errw)
	case "info":
		return cmdInfo(args[1:], out, errw)
	case "version", "--version":
		fmt.Fprintln(out, "ironykeys", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return exitOK
	case "open":
		return cmdOpen(args[1:], out, errw)
	case "close":
		return cmdClose(args[1:], out, errw)
	case "status":
		return cmdStatus(args[1:], out, errw)
	}
	fmt.Fprintf(errw, "ironykeys: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func cmdInfo(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(errw)
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	l, err := volume.Stat(pos[0])
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	fmt.Fprintf(out, "File:          %s\n", pos[0])
	fmt.Fprintf(out, "Size:          %d bytes (%.1f MiB)\n", l.Size, float64(l.Size)/(1<<20))
	fmt.Fprintf(out, "Data area:     %d bytes (%d sectors) at offset %d\n", l.DataSize, l.DataSectors, volume.DataOffset)
	fmt.Fprintf(out, "Backup header: offset %d\n", l.BackupOff)
	if loop, _ := session.LoopFor(pos[0]); loop != "" {
		fmt.Fprintf(out, "Open:          yes (%s)\n", loop)
	} else {
		fmt.Fprintln(out, "Open:          no")
	}
	fmt.Fprintln(out, "The size fits a vault. Whether this is one cannot be known without the password; run 'ironykeys verify'.")
	return exitOK
}

// parseSize reads a size such as 256M, 1G, 4096K or a plain byte count.
func parseSize(v string) (int64, error) {
	if v == "" {
		return 0, errors.New("empty size")
	}
	shift := 0
	switch v[len(v)-1] {
	case 'K', 'k':
		shift = 10
	case 'M', 'm':
		shift = 20
	case 'G', 'g':
		shift = 30
	}
	if shift != 0 {
		v = v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)>>shift {
		return 0, fmt.Errorf("invalid size")
	}
	return n << shift, nil
}

func cmdCreate(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(errw)
	sizeArg := fs.String("size", "256M", "vault size")
	fsType := fs.String("fs", "exfat", "filesystem: exfat, ext4 or none")
	pim := fs.Int("pim", 0, "PIM (0 = default)")
	dry := fs.Bool("dry-run", false, "check and report, write nothing")
	pwfd := fs.Int("password-fd", -1, "read the password from this file descriptor")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	size, err := parseSize(*sizeArg)
	if err != nil {
		fmt.Fprintf(errw, "ironykeys: invalid --size %q\n", *sizeArg)
		return exitUsage
	}
	iters, err := kdf.Iterations(*pim)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitUsage
	}
	switch *fsType {
	case "exfat", "ext4", "none":
	default:
		fmt.Fprintf(errw, "ironykeys: invalid --fs %q\n", *fsType)
		return exitUsage
	}
	l, err := volume.CheckCreate(pos[0], size)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	if *fsType != "none" && !*dry && os.Geteuid() != 0 {
		fmt.Fprintln(errw, "ironykeys: formatting needs root; run with sudo, or pass --fs none for an unformatted vault.")
		return exitError
	}
	if *dry {
		fmt.Fprintf(out, "Filesystem:   %s\n", *fsType)
		fmt.Fprintf(out, "Dry run, nothing written.\n")
		fmt.Fprintf(out, "Would create: %s\n", pos[0])
		fmt.Fprintf(out, "Size:         %d bytes (%.1f MiB), usable data area %d bytes\n", l.Size, float64(l.Size)/(1<<20), l.DataSize)
		fmt.Fprintf(out, "Encryption:   AES-256-XTS, PBKDF2-SHA512 with %d iterations\n", iters)
		return exitOK
	}
	pw, err := readPassword(*pwfd, true)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	defer clear(pw)
	if err := volume.Create(pos[0], size, pw, *pim); err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	// Read the new vault back before reporting success.
	r, err := volume.Verify(pos[0], pw, *pim)
	if err != nil || r.Primary.Err != nil || r.Backup.Err != nil {
		fmt.Fprintln(errw, "ironykeys: the vault was written but did not verify; do not use it:", pos[0])
		return exitError
	}
	defer r.Wipe()
	if os.Geteuid() == 0 {
		// Under sudo the file was created by root; hand it to the user.
		own, err := session.InvokingUser()
		if err == nil {
			err = os.Chown(pos[0], own.UID, own.GID)
		}
		if err == nil && *fsType != "none" {
			err = session.Format(pos[0], r.Primary.Header, r.Layout, *fsType, own)
		}
		if err != nil {
			// This run created the file, so removing it loses nothing.
			os.Remove(pos[0])
			fmt.Fprintln(errw, "ironykeys: create failed, vault removed:", err)
			return exitError
		}
	}
	fmt.Fprintf(out, "Created %s: %d bytes, usable data area %d bytes. Both headers verified.\n", pos[0], l.Size, l.DataSize)
	if *fsType == "none" {
		fmt.Fprintln(out, "The vault has no filesystem.")
	} else {
		fmt.Fprintf(out, "Formatted as %s.\n", *fsType)
	}
	return exitOK
}

func cmdVerify(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(errw)
	pim := fs.Int("pim", 0, "PIM (0 = default)")
	pwfd := fs.Int("password-fd", -1, "read the password from this file descriptor")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	if _, err := kdf.Iterations(*pim); err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitUsage
	}
	// Fail on a bad path before asking for the password.
	if _, err := volume.Stat(pos[0]); err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	pw, err := readPassword(*pwfd, false)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	defer clear(pw)

	r, err := volume.Verify(pos[0], pw, *pim)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	defer r.Wipe()

	fmt.Fprintf(out, "Primary header: %s\n", describe(r.Primary.Err))
	fmt.Fprintf(out, "Backup header:  %s\n", describe(r.Backup.Err))
	pe, be := r.Primary.Err, r.Backup.Err
	switch {
	case pe == nil && be == nil:
		fmt.Fprintf(out, "Vault OK: %d-byte data area, AES-256-XTS, PBKDF2-SHA512.\n", r.Layout.DataSize)
		return exitOK
	case pe == nil || be == nil:
		fmt.Fprintln(errw, "ironykeys: one header is good and one is not; the vault can be opened but should be repaired.")
		return exitOneHeaderOK
	}
	return noHeader(r, errw)
}

// noHeader reports why neither header is usable and returns the exit code.
func noHeader(r *volume.Result, errw io.Writer) int {
	pe, be := r.Primary.Err, r.Backup.Err
	noMatch := func(err error) bool { return err == nil || errors.Is(err, header.ErrNoMatch) }
	switch {
	case errors.Is(pe, volume.ErrProfile) || errors.Is(be, volume.ErrProfile):
		fmt.Fprintln(errw, "ironykeys: the password is right but this volume is outside the supported profile; open it with VeraCrypt.")
		return exitProfile
	case noMatch(pe) && noMatch(be):
		fmt.Fprintln(errw, "ironykeys: wrong password or PIM, or not a VeraCrypt volume of the supported profile.")
		return exitNoMatch
	}
	fmt.Fprintln(errw, "ironykeys: both headers are damaged.")
	return exitError
}

func describe(err error) string {
	if err == nil {
		return "OK"
	}
	return err.Error()
}

// checkPasswordFD refuses a descriptor that cannot be a password handed over
// by the caller. This matters under sudo, which closes every descriptor
// above 2: the number is then reused by a file the Go runtime opens for
// itself (a cgroup file under /sys), and reading it would silently give a
// "password" nobody chose.
func checkPasswordFD(fd int) error {
	hint := fmt.Sprintf("file descriptor %d was not passed to ironykeys (sudo closes descriptors above 2; with sudo use --password-fd 0 and feed the password on standard input)", fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return errors.New(hint)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK:
		return nil
	case syscall.S_IFREG:
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil || strings.HasPrefix(target, "/sys/") || strings.HasPrefix(target, "/proc/") {
			return errors.New(hint)
		}
		return nil
	case syscall.S_IFCHR:
		return fmt.Errorf("file descriptor %d is a terminal or device; omit --password-fd to be prompted", fd)
	}
	return errors.New(hint)
}

// readPassword reads the password from fd, or prompts on the terminal with
// echo off when fd is negative, twice if confirm is set. It is never taken from the command line or
// the environment.
func readPassword(fd int, confirm bool) ([]byte, error) {
	var pw []byte
	if fd >= 0 {
		if err := checkPasswordFD(fd); err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(fd), "password-fd")
		b, err := io.ReadAll(io.LimitReader(f, kdf.MaxPasswordLen+2))
		defer clear(b)
		if err != nil {
			return nil, fmt.Errorf("reading password from fd %d: %w", fd, err)
		}
		trimmed := bytes.TrimRight(b, "\r\n")
		pw = make([]byte, len(trimmed))
		copy(pw, trimmed)
	} else {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, errors.New("no terminal to ask for the password; use --password-fd")
		}
		defer tty.Close()
		fmt.Fprint(tty, "Vault password: ")
		pw, err = term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return nil, err
		}
		if confirm {
			fmt.Fprint(tty, "Repeat password: ")
			again, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(tty)
			same := err == nil && bytes.Equal(pw, again)
			clear(again)
			if !same {
				clear(pw)
				return nil, errors.New("passwords do not match")
			}
		}
	}
	if len(pw) == 0 || len(pw) > kdf.MaxPasswordLen {
		clear(pw)
		return nil, errors.New("password must be 1 to 128 bytes")
	}
	return pw, nil
}
