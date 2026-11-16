// Package session opens and closes vaults: loop device, dm-crypt mapping,
// filesystem and mount, plus the small state file that records an open
// vault. Everything here that changes the system needs root.
package session

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hexawulf/ironykeys/internal/header"
	"github.com/hexawulf/ironykeys/internal/volume"
)

// StateDir holds one JSON file per open vault. /run is cleared on reboot,
// like the mappings themselves. It holds no secrets.
var StateDir = "/run/ironykeys"

const mappingPrefix = "ironykeys-"

var (
	// ErrBusy means the vault, its name or its mountpoint is in use.
	ErrBusy = errors.New("busy")
	// ErrNoFS means the vault opened but holds no filesystem.
	ErrNoFS = errors.New("vault has no filesystem")
	// ErrNotOpen means no open vault matches.
	ErrNotOpen = errors.New("not open")

	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// State describes one open vault.
type State struct {
	Name              string    `json:"name"`
	Vault             string    `json:"vault"`
	Loop              string    `json:"loop"`
	Mapping           string    `json:"mapping"`
	Mountpoint        string    `json:"mountpoint"`
	FS                string    `json:"fs"`
	ReadOnly          bool      `json:"read_only"`
	CreatedMountpoint bool      `json:"created_mountpoint"`
	Opened            time.Time `json:"opened"`
}

// Owner is the user a vault is opened for.
type Owner struct {
	UID, GID int
	Home     string
}

// InvokingUser returns the user behind sudo, or the current user.
func InvokingUser() (Owner, error) {
	uid := os.Getuid()
	if s := os.Getenv("SUDO_UID"); s != "" && os.Geteuid() == 0 {
		n, err := strconv.Atoi(s)
		if err != nil {
			return Owner{}, fmt.Errorf("bad SUDO_UID %q", s)
		}
		uid = n
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return Owner{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return Owner{}, err
	}
	return Owner{UID: uid, GID: gid, Home: u.HomeDir}, nil
}

// NameFor derives the default vault name from its file name.
func NameFor(vaultPath string) (string, error) {
	base := filepath.Base(vaultPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if err := CheckName(name); err != nil {
		return "", fmt.Errorf("cannot derive a name from %q; pass --name", base)
	}
	return name, nil
}

// CheckName validates a vault name.
func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: use letters, digits, '-' and '_'", name)
	}
	return nil
}

// tool runs a system program with a fixed PATH and returns its output.
func tool(stdin []byte, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s: %v: %s", name, err, text)
	}
	return text, nil
}

// LoopFor returns the loop device backed by the file at path, or "" if
// there is none. It reads sysfs and needs no privileges. It also sees a
// vault opened by VeraCrypt or cryptsetup.
func LoopFor(path string) (string, error) {
	abs, err := resolve(path)
	if err != nil {
		return "", err
	}
	files, _ := filepath.Glob("/sys/block/loop*/loop/backing_file")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.TrimSuffix(string(b), "\n") == abs {
			return "/dev/" + strings.Split(f, "/")[3], nil
		}
	}
	return "", nil
}

func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// mounted reports whether something is mounted exactly at dir.
func mounted(dir string) bool {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && unescape(f[4]) == dir {
			return true
		}
	}
	return false
}

// unescape decodes the octal escapes the kernel uses in mountinfo.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func statePath(name string) string { return filepath.Join(StateDir, name+".json") }

func writeState(s *State) error {
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(s.Name) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(s.Name))
}

// List returns the recorded open vaults.
func List() ([]State, error) {
	files, err := filepath.Glob(filepath.Join(StateDir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []State
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var s State
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// Live reports whether the mapping recorded in s still exists.
func (s *State) Live() bool {
	_, err := os.Stat("/dev/mapper/" + s.Mapping)
	return err == nil
}

// Find returns the open vault matching target, which is a name or the path
// of a vault file.
func Find(target string) (*State, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	abs, _ := resolve(target)
	for i := range all {
		if all[i].Name == target || (abs != "" && all[i].Vault == abs) {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("%s: %w", target, ErrNotOpen)
}

// attach maps the vault's data area at /dev/mapper/<mapping> and returns
// the loop device. The master key reaches dmsetup on stdin, never in an
// argument list.
func attach(vault, mapping string, h *header.Header, l volume.Layout, readOnly bool) (loop string, err error) {
	args := []string{"--find", "--show"}
	if readOnly {
		args = append(args, "--read-only")
	}
	if loop, err = tool(nil, "losetup", append(args, vault)...); err != nil {
		return "", err
	}
	table := make([]byte, 0, 256)
	table = fmt.Appendf(table, "0 %d crypt aes-xts-plain64 ", l.DataSectors)
	table = hex.AppendEncode(table, h.MasterKey[:])
	table = fmt.Appendf(table, " %d %s %d\n", volume.DataOffset/volume.SectorSize, loop, volume.DataOffset/volume.SectorSize)
	defer clear(table)

	dmArgs := []string{"create", mapping}
	if readOnly {
		dmArgs = append(dmArgs, "--readonly")
	}
	if _, err = tool(table, "dmsetup", dmArgs...); err != nil {
		tool(nil, "losetup", "-d", loop)
		return "", err
	}
	return loop, nil
}

func detach(mapping, loop string) error {
	var first error
	if _, err := os.Stat("/dev/mapper/" + mapping); err == nil {
		// --retry: udev often still has the device open for a moment
		// after mkfs or umount, which makes a plain remove fail as busy.
		if _, err := tool(nil, "dmsetup", "remove", "--retry", mapping); err != nil {
			first = err
		}
	}
	if loop != "" && first == nil {
		if _, err := os.Stat(loop); err == nil {
			if _, err := tool(nil, "losetup", "-d", loop); err != nil {
				first = err
			}
		}
	}
	return first
}

// Format writes a new filesystem into a closed vault. fs is "exfat" or
// "ext4". It destroys whatever the data area held.
func Format(vault string, h *header.Header, l volume.Layout, fs string, own Owner) error {
	if fs != "exfat" && fs != "ext4" {
		return fmt.Errorf("unsupported filesystem %q", fs)
	}
	abs, err := resolve(vault)
	if err != nil {
		return err
	}
	if loop, _ := LoopFor(abs); loop != "" {
		return fmt.Errorf("%s is attached to %s: %w", abs, loop, ErrBusy)
	}
	mapping := fmt.Sprintf("%sformat-%d", mappingPrefix, os.Getpid())
	loop, err := attach(abs, mapping, h, l, false)
	if err != nil {
		return err
	}
	dev := "/dev/mapper/" + mapping
	if fs == "exfat" {
		_, err = tool(nil, "mkfs.exfat", "-L", "IRONYKEYS", dev)
	} else {
		_, err = tool(nil, "mkfs.ext4", "-q", "-m", "0", "-L", "IronyKeys",
			"-E", fmt.Sprintf("root_owner=%d:%d,root_perms=700", own.UID, own.GID), dev)
	}
	if derr := detach(mapping, loop); err == nil {
		err = derr
	}
	return err
}

// OpenOptions are the inputs to Open.
type OpenOptions struct {
	Vault      string
	Name       string // "" derives it from the file name
	Mountpoint string // "" means <home>/IronyKeys/<name>
	ReadOnly   bool
	Header     *header.Header
	Layout     volume.Layout
	Owner      Owner
}

// Open attaches, maps and mounts a vault and records it. On any failure it
// undoes the steps already taken.
func Open(o OpenOptions) (st *State, err error) {
	abs, err := resolve(o.Vault)
	if err != nil {
		return nil, err
	}
	name := o.Name
	if name == "" {
		if name, err = NameFor(abs); err != nil {
			return nil, err
		}
	} else if err = CheckName(name); err != nil {
		return nil, err
	}
	mapping := mappingPrefix + name
	if loop, _ := LoopFor(abs); loop != "" {
		return nil, fmt.Errorf("%s is already open (%s): %w", abs, loop, ErrBusy)
	}
	if _, serr := os.Stat("/dev/mapper/" + mapping); serr == nil {
		return nil, fmt.Errorf("the name %q is in use by another open vault: %w", name, ErrBusy)
	}

	mp := o.Mountpoint
	if mp == "" {
		mp = filepath.Join(o.Owner.Home, "IronyKeys", name)
	}
	if mp, err = filepath.Abs(mp); err != nil {
		return nil, err
	}

	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()

	created, err := prepareMountpoint(mp, o.Owner, &undo)
	if err != nil {
		return nil, err
	}

	loop, err := attach(abs, mapping, o.Header, o.Layout, o.ReadOnly)
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() { detach(mapping, loop) })
	dev := "/dev/mapper/" + mapping

	// blkid exits 2 when it finds no filesystem signature.
	fs, _ := tool(nil, "blkid", "-o", "value", "-s", "TYPE", dev)
	var opts string
	switch fs {
	case "exfat":
		opts = fmt.Sprintf("nodev,nosuid,noexec,uid=%d,gid=%d,umask=077", o.Owner.UID, o.Owner.GID)
	case "ext4":
		opts = "nodev,nosuid,noexec"
	case "":
		return nil, ErrNoFS
	default:
		return nil, fmt.Errorf("vault holds a %q filesystem; only exfat and ext4 are supported", fs)
	}
	if o.ReadOnly {
		opts = "ro," + opts
	}
	if _, err = tool(nil, "mount", "-t", fs, "-o", opts, dev, mp); err != nil {
		return nil, err
	}
	undo = append(undo, func() { tool(nil, "umount", mp) })

	st = &State{
		Name: name, Vault: abs, Loop: loop, Mapping: mapping, Mountpoint: mp,
		FS: fs, ReadOnly: o.ReadOnly, CreatedMountpoint: created,
		Opened: time.Now().UTC().Truncate(time.Second),
	}
	if err = writeState(st); err != nil {
		return nil, err
	}
	return st, nil
}

// prepareMountpoint makes sure mp is an empty directory with nothing
// mounted on it, creating it (and missing parents) for the owner if needed.
func prepareMountpoint(mp string, own Owner, undo *[]func()) (created bool, err error) {
	fi, err := os.Lstat(mp)
	switch {
	case err == nil:
		if !fi.IsDir() {
			return false, fmt.Errorf("mountpoint %s is not a directory", mp)
		}
		if mounted(mp) {
			return false, fmt.Errorf("something is already mounted at %s: %w", mp, ErrBusy)
		}
		entries, err := os.ReadDir(mp)
		if err != nil {
			return false, err
		}
		if len(entries) > 0 {
			return false, fmt.Errorf("mountpoint %s is not empty", mp)
		}
		return false, nil
	case !errors.Is(err, os.ErrNotExist):
		return false, err
	}
	// Create missing directories top down, each owned by the user.
	var missing []string
	for d := mp; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		}
		missing = append([]string{d}, missing...)
		if d == filepath.Dir(d) {
			break
		}
	}
	for _, d := range missing {
		if err := os.Mkdir(d, 0o700); err != nil {
			return false, err
		}
		dir := d
		*undo = append(*undo, func() { os.Remove(dir) })
		if err := os.Chown(d, own.UID, own.GID); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Close unmounts and unmaps the open vault matching target (a name or a
// vault path). If the mountpoint is busy nothing is changed.
func Close(target string) (*State, error) {
	st, err := Find(target)
	if err != nil {
		return nil, err
	}
	if mounted(st.Mountpoint) {
		if _, err := tool(nil, "umount", st.Mountpoint); err != nil {
			return st, fmt.Errorf("%w: %v", ErrBusy, err)
		}
	}
	if err := detach(st.Mapping, st.Loop); err != nil {
		return st, err
	}
	if err := os.Remove(statePath(st.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return st, err
	}
	if st.CreatedMountpoint {
		os.Remove(st.Mountpoint) // only succeeds if empty
	}
	return st, nil
}
