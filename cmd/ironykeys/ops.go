package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hexawulf/ironykeys/internal/kdf"
	"github.com/hexawulf/ironykeys/internal/session"
	"github.com/hexawulf/ironykeys/internal/volume"
)

func needRoot(what string, errw io.Writer) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(errw, "ironykeys: %s needs root; run it with sudo.\n", what)
	return false
}

func cmdOpen(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(errw)
	pim := fs.Int("pim", 0, "PIM (0 = default)")
	ro := fs.Bool("read-only", false, "mount read-only")
	name := fs.String("name", "", "vault name (default: from the file name)")
	pwfd := fs.Int("password-fd", -1, "read the password from this file descriptor")
	pos, err := parse(fs, args)
	if err != nil || len(pos) < 1 || len(pos) > 2 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	if _, err := kdf.Iterations(*pim); err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitUsage
	}
	if !needRoot("open", errw) {
		return exitError
	}
	vault := pos[0]
	mountpoint := ""
	if len(pos) == 2 {
		mountpoint = pos[1]
	}
	// Cheap checks first, so a doomed open does not ask for the password.
	if _, err := volume.Stat(vault); err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	if loop, _ := session.LoopFor(vault); loop != "" {
		fmt.Fprintf(errw, "ironykeys: %s is already open (%s).\n", vault, loop)
		return exitBusy
	}
	own, err := session.InvokingUser()
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	pw, err := readPassword(*pwfd, false)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	defer clear(pw)

	r, err := volume.Verify(vault, pw, *pim)
	if err != nil {
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	defer r.Wipe()
	h := r.Usable()
	if h == nil {
		return noHeader(r, errw)
	}
	if r.Primary.Err != nil {
		fmt.Fprintln(errw, "ironykeys: warning: the primary header is damaged; opening with the backup header. Copy your data out and recreate the vault.")
	} else if r.Backup.Err != nil {
		fmt.Fprintln(errw, "ironykeys: warning: the backup header is damaged; the vault opens but has no spare header.")
	}

	st, err := session.Open(session.OpenOptions{
		Vault: vault, Name: *name, Mountpoint: mountpoint, ReadOnly: *ro,
		Header: h, Layout: r.Layout, Owner: own,
	})
	switch {
	case errors.Is(err, session.ErrBusy):
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitBusy
	case errors.Is(err, session.ErrNoFS):
		fmt.Fprintln(errw, "ironykeys: the password is right but the vault holds no filesystem; nothing was mounted.")
		return exitError
	case err != nil:
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	mode := "read-write"
	if st.ReadOnly {
		mode = "read-only"
	}
	fmt.Fprintf(out, "Opened %s at %s (%s, %s). Close it with: sudo ironykeys close %s\n",
		st.Name, st.Mountpoint, st.FS, mode, st.Name)
	return exitOK
}

func cmdClose(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("close", flag.ContinueOnError)
	fs.SetOutput(errw)
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	if !needRoot("close", errw) {
		return exitError
	}
	st, err := session.Close(pos[0])
	switch {
	case errors.Is(err, session.ErrNotOpen):
		fmt.Fprintf(errw, "ironykeys: %s is not open.\n", pos[0])
		return exitError
	case errors.Is(err, session.ErrBusy):
		fmt.Fprintf(errw, "ironykeys: %s is in use and stays open: %v\n", st.Mountpoint, err)
		return exitBusy
	case err != nil:
		fmt.Fprintln(errw, "ironykeys:", err)
		return exitError
	}
	fmt.Fprintf(out, "Closed %s (%s).\n", st.Name, st.Vault)
	return exitOK
}

func cmdStatus(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(errw)
	quiet := fs.Bool("quiet", false, "no output; exit 4 if open, 0 if closed")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 1 || (*quiet && len(pos) != 1) {
		fmt.Fprint(errw, usage)
		return exitUsage
	}
	if len(pos) == 0 {
		all, err := session.List()
		if err != nil {
			fmt.Fprintln(errw, "ironykeys:", err)
			return exitError
		}
		if len(all) == 0 {
			fmt.Fprintln(out, "No vaults are open.")
			return exitOK
		}
		for _, s := range all {
			printState(out, &s)
		}
		return exitOK
	}

	// A vault counts as open if IronyKeys recorded it, or if any loop
	// device is backed by the file (VeraCrypt or cryptsetup opened it).
	st, ferr := session.Find(pos[0])
	if ferr != nil && !errors.Is(ferr, session.ErrNotOpen) {
		fmt.Fprintln(errw, "ironykeys:", ferr)
		return exitError
	}
	loop, _ := session.LoopFor(pos[0])
	isOpen := (st != nil && st.Live()) || loop != ""
	if *quiet {
		if isOpen {
			return exitBusy
		}
		return exitOK
	}
	switch {
	case st != nil:
		printState(out, st)
	case loop != "":
		fmt.Fprintf(out, "%s is open, but not by IronyKeys (attached to %s).\n", pos[0], loop)
	default:
		fmt.Fprintf(out, "%s is closed.\n", pos[0])
	}
	if isOpen {
		return exitBusy
	}
	return exitOK
}

func printState(out io.Writer, s *session.State) {
	mode := "read-write"
	if s.ReadOnly {
		mode = "read-only"
	}
	note := ""
	if !s.Live() {
		note = "  [stale record: the mapping is gone]"
	}
	fmt.Fprintf(out, "%s  %s\n  mounted at %s (%s, %s) since %s%s\n",
		s.Name, s.Vault, s.Mountpoint, s.FS, mode, s.Opened.Local().Format("2006-01-02 15:04:05"), note)
}
