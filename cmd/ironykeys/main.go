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

	"golang.org/x/term"

	"ironykeys/internal/header"
	"ironykeys/internal/kdf"
	"ironykeys/internal/volume"
)

var version = "0.1.0-dev"

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
  ironykeys verify <vault> [--pim N] [--password-fd N]
  ironykeys info   <vault>
  ironykeys version

verify  Check the password against both headers. Never mounts.
info    Show what is knowable without the password.

Not implemented yet: create, open, close, status.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	switch args[0] {
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
	case "create", "open", "close", "status":
		fmt.Fprintf(errw, "ironykeys: %q is not implemented yet\n", args[0])
		return exitError
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
	fmt.Fprintln(out, "The size fits a vault. Whether this is one cannot be known without the password; run 'ironykeys verify'.")
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
	pw, err := readPassword(*pwfd)
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
	case errors.Is(pe, volume.ErrProfile) || errors.Is(be, volume.ErrProfile):
		fmt.Fprintln(errw, "ironykeys: the password is right but this volume is outside the supported profile; open it with VeraCrypt.")
		return exitProfile
	case errors.Is(pe, header.ErrNoMatch) && errors.Is(be, header.ErrNoMatch):
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

// readPassword reads the password from fd, or prompts on the terminal with
// echo off when fd is negative. It is never taken from the command line or
// the environment.
func readPassword(fd int) ([]byte, error) {
	var pw []byte
	if fd >= 0 {
		f := os.NewFile(uintptr(fd), "password-fd")
		if f == nil {
			return nil, fmt.Errorf("file descriptor %d is not open", fd)
		}
		b, err := io.ReadAll(io.LimitReader(f, kdf.MaxPasswordLen+2))
		if err != nil {
			return nil, fmt.Errorf("reading password from fd %d: %w", fd, err)
		}
		pw = bytes.TrimRight(b, "\r\n")
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
	}
	if len(pw) == 0 || len(pw) > kdf.MaxPasswordLen {
		clear(pw)
		return nil, errors.New("password must be 1 to 128 bytes")
	}
	return pw, nil
}
