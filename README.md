# 🔐 IronyKeys

[![CI](https://github.com/hexawulf/ironykeys/actions/workflows/ci.yml/badge.svg)](https://github.com/hexawulf/ironykeys/actions/workflows/ci.yml)

**A small, zero-bloat command-line tool for Linux that keeps secrets in one fixed-size encrypted file.**
The vault uses the standard VeraCrypt volume format (`AES-256-XTS`, `PBKDF2-HMAC-SHA512`), so the official VeraCrypt and `cryptsetup` can open it without IronyKeys.

> *Named for the irony of keeping your most private files — SSH keys, PGP keys, and recovery codes — on someone else's cloud.*

```text
$ sudo ironykeys create ~/vaults/keys.vc
Vault password:
Repeat password:
Created /home/you/vaults/keys.vc: 268435456 bytes, usable data area 268173312 bytes. Both headers verified.
Formatted as exfat.

$ sudo ironykeys open ~/vaults/keys.vc
Vault password:
Opened keys at /home/you/IronyKeys/keys (exfat, read-write). Close it with: sudo ironykeys close keys

$ sudo ironykeys close keys
Closed keys (/home/you/vaults/keys.vc).
```

---

## 🧭 Contents

- [✨ What it is and is not](#-what-it-is-and-is-not)
- [📌 Status](#-status)
- [⚙️ Requirements](#️-requirements)
- [🛠️ Build and install](#️-build-and-install)
- [🚀 Quick start](#-quick-start)
- [📖 Command reference](#-command-reference)
- [🔑 Passwords, sudo and scripts](#-passwords-sudo-and-scripts)
- [🔢 Exit codes](#-exit-codes)
- [🛟 Opening a vault without IronyKeys](#-opening-a-vault-without-ironykeys)
- [☁️ Backups and restore](#️-backups-and-restore)
- [🛡️ Security model and limits](#️-security-model-and-limits)
- [🩺 Troubleshooting](#-troubleshooting)
- [🧪 Testing](#-testing)
- [📂 Project layout](#-project-layout)
- [⚖️ Licence](#️-licence)

---

## ✨ What it is and is not

**IronyKeys is:**

- 📦 **One file, fixed size.** You choose the size when you create the vault (`256 MiB` by default). The file never grows or shrinks and reveals nothing about how full it is.
- 🤝 **VeraCrypt-compatible.** A vault made by IronyKeys opens in VeraCrypt on Linux, Windows and macOS, and in `cryptsetup`. A VeraCrypt volume of the same profile opens in IronyKeys. If this tool disappears, your data does not.
- ⚡ **Small and fast.** About 1,500 lines of Go and one static binary. Key derivation comes from Go's standard library, the header cipher from `golang.org/x/crypto`, and the Linux kernel (`dm-crypt`) encrypts the data. `open` checks only the primary header in the normal case (falling back to the backup header on damage), and `verify` checks both headers in parallel across CPU cores.

**IronyKeys is not:**

- **A fork of VeraCrypt.** It shares no code with it. It reads and writes the same on-disk format, and only one profile of it (see below).
- **A key manager.** It gives you an encrypted directory. What you put in it and how you organise it is up to you.
- **Audited.** Nobody independent has reviewed this code. Its correctness rests on tests against VeraCrypt and `cryptsetup`. Keep a second copy of anything you cannot afford to lose.

### The one supported profile

| Property | Value |
|---|---|
| **Volume type** | Normal (non-hidden), file-hosted |
| **Cipher** | AES-256 in XTS mode |
| **Key derivation** | PBKDF2-HMAC-SHA512, 500,000 iterations (or `15000 + PIM × 1000`) |
| **Password** | 1–128 bytes, optional PIM |
| **Filesystem inside** | `exFAT` (default) or `ext4` |

Hidden volumes, keyfiles, cipher cascades, other ciphers or hashes, system encryption and legacy TrueCrypt volumes are not supported. Such a volume is reported as *"wrong password or not a VeraCrypt volume of the supported profile"*; open it with VeraCrypt instead.

---

## 📌 Status

Version `0.2.0`. All commands below are implemented and tested on `arm64` (Raspberry Pi 5, Ubuntu 26.04) and `amd64` against VeraCrypt 1.26.31 and `cryptsetup` 2.8.4. The full design and byte layout are in [SPEC.md](SPEC.md).

---

## ⚙️ Requirements

- Linux with `dm-crypt` and loop devices (any mainstream distribution kernel).
- Root, through `sudo`, for `open`, `close` and for formatting in `create`. `verify`, `passwd`, `header-restore`, `info`, `status` and `create --fs none` need no root.
- Standard system tools on the `PATH`: `losetup`, `dmsetup`, `blkid`, `mount`, `umount`, plus `mkfs.exfat` (package `exfatprogs`) or `mkfs.ext4` (package `e2fsprogs`) for the filesystem you choose.
- Kernel exFAT support for exFAT vaults (in mainline since Linux 5.7).
- Go 1.26 or newer to build.

On Debian or Ubuntu:

```bash
sudo apt install golang-go dmsetup exfatprogs e2fsprogs util-linux
```

---

## 🛠️ Build and install

```bash
git clone https://github.com/hexawulf/ironykeys.git
cd ironykeys
make test       # unit tests, no root needed
make build      # produces ./ironykeys, statically linked
make install    # copies it to /usr/local/bin (uses sudo)
ironykeys version
```

Without `make`:

```bash
CGO_ENABLED=0 go build -o ironykeys ./cmd/ironykeys
sudo install -m 0755 ironykeys /usr/local/bin/ironykeys
```

`make dist` cross-compiles `dist/ironykeys-linux-arm64` and `dist/ironykeys-linux-amd64` with a `SHA256SUMS` file. The binary has no runtime library dependencies, so you can copy it directly to another host of the same architecture.

---

## 🚀 Quick start

### 1. Create a vault

```bash
mkdir -m 700 -p ~/vaults
sudo ironykeys create ~/vaults/keys.vc
```

You are asked for the password twice. The result is a `256 MiB` file owned by you, mode `600`, formatted as `exFAT`.

> ⚠️ **Write the password down somewhere safe before you start.** There is no recovery: without the password the vault cannot be opened by anyone.

To see what would happen without writing anything:

```bash
ironykeys create ~/vaults/keys.vc --size 64M --dry-run
```

`create` never overwrites: if the path exists, it stops.

### 2. Open it

```bash
sudo ironykeys open ~/vaults/keys.vc
```

The vault is mounted at `~/IronyKeys/keys` (the name comes from the file name without its extension). The directory is readable only by you.

### 3. Use it

```bash
cp ~/.ssh/id_ed25519 ~/IronyKeys/keys/
ls -la ~/IronyKeys/keys
```

### 4. Close it

```bash
sudo ironykeys close keys
```

Closing unmounts the filesystem and removes the key from the kernel. Until you close it, anything running as you can read the files. Close the vault when you are done.

### 5. Check on it

```bash
ironykeys status                    # list open vaults
ironykeys verify ~/vaults/keys.vc   # test the password against both headers without mounting
```

---

## 📖 Command reference

```text
ironykeys create         <vault> [--size 256M] [--fs exfat|ext4|none] [--pim N] [--dry-run]
ironykeys open           <vault> [<mountpoint>] [--read-only] [--name NAME] [--pim N]
ironykeys close          <vault|name>
ironykeys status         [<vault|name>] [--quiet]
ironykeys verify         <vault> [--pim N]
ironykeys passwd         <vault> [--pim N] [--new-pim N] [--dry-run]
ironykeys header-restore <vault> [--pim N] [--dry-run]
ironykeys info           <vault>
ironykeys version
```

`create`, `open`, `verify`, `passwd` and `header-restore` also take `--password-fd N` (see [🔑 Passwords, sudo and scripts](#-passwords-sudo-and-scripts)). Flags may come before or after the vault path.

### `create`

Writes a new vault and formats it.

| Option | Meaning |
|---|---|
| `--size` | Total file size. Takes `K`, `M` or `G` (powers of 1024). Minimum `4M`, default `256M`. Must be a multiple of 512 bytes. |
| `--fs` | Filesystem inside: `exfat` (default), `ext4`, or `none` for an unformatted vault. |
| `--pim` | VeraCrypt's Personal Iterations Multiplier. `0` (default) means the standard 500,000 iterations. If you set one, you need it every time you open the vault. |
| `--dry-run` | Check the path, size and free space, report, write nothing. |

How it works: the whole file is filled with random bytes first, and the two headers are written last. An interrupted run therefore leaves a file that does not verify, and a failed run removes the file it started. Before reporting success, `create` reads the vault back and verifies both headers.

Formatting needs root. `create --fs none` does not, and produces a valid vault that VeraCrypt or `cryptsetup` can format later.

About `256 KiB` of the file is used by the headers, so a `256 MiB` vault has a `268,173,312`-byte data area; the filesystem takes a little more.

**`exFAT` or `ext4`?**

| Feature | `exFAT` | `ext4` |
|---|---|---|
| Opens on Windows and macOS (through VeraCrypt) | Yes | No |
| Stores Unix owners and permissions | No | Yes |
| What you see | Every file is `rwx------`, owned by you | Real permissions; root directory is yours, mode `700` |

### `open`

Checks the password, attaches the file to a loop device, creates the `dm-crypt` mapping `/dev/mapper/ironykeys-<name>` and mounts it.

| Option | Meaning |
|---|---|
| `<mountpoint>` | Where to mount. Default `~/IronyKeys/<name>`. |
| `--name` | Vault name. Default: the file name without its extension. Allowed: letters, digits, `-`, `_`. |
| `--read-only` | Mount read-only. Nothing in the vault file changes. |
| `--pim` | The PIM given at creation, if any. |

Details:

- Mount options are `nodev,nosuid,noexec`. For `exFAT`, files belong to the user who ran `sudo`, with `umask=077`.
- An existing mountpoint must be an empty directory with nothing mounted on it. A mountpoint that `open` creates is removed again by `close`.
- If any step fails, the steps already taken are undone. Nothing is left mapped or mounted.
- `open` checks the primary header first for speed. If the primary header is damaged, the backup header at the end of the file is used automatically and a warning is printed. Run `ironykeys header-restore` after closing the vault to repair the damaged header in place.

### `close`

Unmounts the filesystem, removes the mapping and detaches the loop device. Takes the vault name or the path of the vault file.

If something still uses the mountpoint (a shell whose current directory is inside it, an open file), `close` changes nothing and exits with code `4`. The vault stays fully usable; stop whatever is using it and try again.

### `status`

- `ironykeys status` lists the open vaults.
- `ironykeys status <vault|name>` says whether one vault is open.
- `ironykeys status --quiet <vault>` prints nothing and only sets the exit code: `4` if open, `0` if closed.

`status` needs no root. It reads the kernel's loop devices, so it also reports a vault that VeraCrypt or `cryptsetup` has open.

### `verify`

Checks the password against both headers in parallel and reports each one. It only reads the file, never mounts it and needs no root.

```text
$ ironykeys verify ~/vaults/keys.vc
Vault password:
Primary header: OK
Backup header:  OK
Vault OK: 268173312-byte data area, AES-256-XTS, PBKDF2-SHA512.
```

### `passwd`

Changes the vault password (and optionally its PIM) in place. It decrypts a usable header with the current password to recover the master key, then re-encrypts both the backup and primary headers with fresh 64-byte random salts under the new password and verifies both. The data area is untouched, and no root is needed. Refuses to run while the vault is open.

| Option | Meaning |
|---|---|
| `--pim` | The current PIM, if the vault uses one. |
| `--new-pim` | New PIM (`0` for the default 500,000 iterations). If omitted, the current PIM is kept. |
| `--dry-run` | Verify the current password and report what would be re-encrypted, writing nothing. |

With `--password-fd N`, supply two lines (`old_password\nnew_password\n`).

### `header-restore`

Repairs a damaged primary or backup header in place from the intact one, using a fresh 64-byte random salt, and verifies both headers afterwards. Needs no root and refuses to run while the vault is open.

| Option | Meaning |
|---|---|
| `--pim` | The vault's PIM, if any. |
| `--dry-run` | Check both headers and report which one would be restored, writing nothing. |

### `info`

Shows what can be known without the password: file size, data area, the offset of the backup header and whether the vault is open. A vault is indistinguishable from random data without its password, so `info` can only say that the size fits, not that the file is a vault.

---

## 🔑 Passwords, sudo and scripts

- By default the password is asked on the terminal with echo off.
- There is no `--password` option and no environment variable. A password on a command line would be visible in the process list and in shell history.
- For scripts, `--password-fd N` reads the password from an open file descriptor. A trailing newline is ignored.

Without `sudo`, any descriptor works:

```bash
ironykeys verify vault.vc --password-fd 3 3< <(pass show ironykeys)
```

**Under `sudo`, use descriptor `0`.** `sudo` closes every descriptor above `2` before it starts the program, so descriptor `3` never arrives:

```bash
pass show ironykeys | sudo ironykeys open ~/vaults/keys.vc --password-fd 0
```

IronyKeys refuses a descriptor that the caller did not really pass, and says so. This check exists because of a bug found during development: with the descriptor closed by `sudo`, the same number was reused by a file the Go runtime opens for itself, and a vault was created with that file's contents as its password.

With `--password-fd`, `create` cannot ask twice. Run `ironykeys verify` afterwards with the password typed by hand if you want to be sure of it.

---

## 🔢 Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. `status --quiet`: the vault is closed. |
| `1` | General error. |
| `2` | Usage error. |
| `3` | Wrong password or PIM, or not a VeraCrypt volume of the supported profile. |
| `4` | Busy: the vault is open, or the mountpoint is in use. `status <vault>`: the vault is open. |
| `5` | The password is right but the volume is outside the supported profile. |
| `6` | `verify` only: one of the two headers is damaged, the other is good. |

---

## 🛟 Opening a vault without IronyKeys

This is the escape hatch. Nothing below needs IronyKeys.

### VeraCrypt (Linux, Windows, macOS)

In the graphical program: **Select File**, choose the vault, **Mount**, type the password. If you created the vault with a PIM, tick **Use PIM**.

On the command line:

```bash
veracrypt --text ~/vaults/keys.vc /mnt/keys     # mount
veracrypt --text -d ~/vaults/keys.vc            # dismount
```

Only `exFAT` vaults are readable on Windows and macOS.

### `cryptsetup` (Linux)

```bash
sudo cryptsetup open --type tcrypt --veracrypt ~/vaults/keys.vc keys
sudo mount /dev/mapper/keys /mnt/keys
# ...
sudo umount /mnt/keys
sudo cryptsetup close keys
```

Add `--veracrypt-pim N` if the vault has a PIM. To print the header fields:

```bash
sudo cryptsetup tcryptDump --veracrypt ~/vaults/keys.vc
```

---

## ☁️ Backups and restore

A vault is one file, so a backup is a copy of that file. Three rules:

1. **Copy only a closed vault.** A vault that is open may be half-written. Guard every backup with `ironykeys status --quiet`.
2. **Keep a checksum next to each copy.** The encryption keeps the contents secret but does not detect tampering or bit rot (see the next section). A SHA-256 recorded at backup time does.
3. **The whole file is re-uploaded whenever it changes.** There are no partial updates. This is the reason to keep the vault small.

A minimal backup with `rclone`:

```bash
#!/usr/bin/env bash
set -euo pipefail
VAULT="$HOME/vaults/keys.vc"
DEST="remote:backups/keys/$(date +%F)"

rc=0; ironykeys status --quiet "$VAULT" || rc=$?
if [ "$rc" -ne 0 ]; then echo "vault is open or status failed (exit $rc)" >&2; exit 1; fi

STAGE="$(mktemp -d "$(dirname "$VAULT")/.backup.XXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT
ln "$VAULT" "$STAGE/keys.vc"                       # hard link, no extra space
( cd "$STAGE" && sha256sum keys.vc > keys.vc.sha256 )

rclone copy "$STAGE" "$DEST"
rclone check --download "$STAGE" "$DEST"           # compare content, not just size
```

The vault file changes only when you write to it while it is open, so a backup job can compare checksums and skip the upload when nothing changed.

### Restore

```bash
rclone copy remote:backups/keys/2026-11-16 ./restore
cd restore
sha256sum -c keys.vc.sha256     # the copy is intact
ironykeys verify keys.vc        # the password still opens it
sudo ironykeys open keys.vc
```

Do a restore test on a second machine before you rely on a vault as the only copy of anything.

### Growing a vault

A vault is a fixed-size file by design and is never resized in place. To move to a larger vault, create a new one, open both, and copy the files over (the old vault stays intact until you verify the new one):

```bash
sudo ironykeys create ~/vaults/keys-512m.vc --size 512M
sudo ironykeys open ~/vaults/keys.vc
sudo ironykeys open ~/vaults/keys-512m.vc
cp -a ~/IronyKeys/keys/. ~/IronyKeys/keys-512m/
sudo ironykeys close keys
sudo ironykeys close keys-512m
```

---

## 🛡️ Security model and limits

### What a vault protects against

- Someone who obtains the vault file (a cloud provider, a stolen disk or backup) and does not know the password. They see random-looking bytes and cannot tell how much of the vault is used.

### What it does not protect against

- **A compromised machine while the vault is open.** Any process running as you or as root can read the mounted files. Root can also read the key from the kernel.
- **A weak password.** Key derivation slows guessing down; it does not save a short or reused password. Use a long passphrase.
- **Tampering.** XTS encryption has no integrity check. Someone who can modify the file can corrupt data without being detected by the format itself. Keep checksums outside the vault, as in the backup section.
- **Loss of the password.** There is no recovery key and no back door.
- **Leaks outside the vault.** Files you copy out, editor swap files, shell history and the like are not covered.

### Things to know

- The mapping key sits in kernel memory while a vault is open, as with any `dm-crypt` device. `close` removes it; so does a reboot.
- IronyKeys locks its memory (`mlockall`) where permitted, clears key buffers after use and passes the key to `dmsetup` on standard input, never as an argument. Go's garbage collector can still leave copies in process memory until the process exits, which is a moment later. This is best effort, not a guarantee.
- The vault file is created with mode `600`. The state files under `/run/ironykeys/` hold paths and device names, no secrets.
- A Raspberry Pi 4 has no hardware AES; a Pi 5 does. For a key vault of a few hundred megabytes the difference does not matter.
- The code has not been audited. Read [SPEC.md](SPEC.md) and the source before you trust it with something important.

---

## 🩺 Troubleshooting

**"wrong password or PIM, or not a VeraCrypt volume of the supported profile"**
The three cases cannot be told apart; that is a property of the format. Check the keyboard layout, check whether the vault was created with a PIM, and try `ironykeys verify`. A volume that uses another cipher or hash opens only in VeraCrypt.

**"open needs root; run it with sudo"**
Mapping and mounting are privileged operations.

**"file descriptor 3 was not passed to ironykeys"**
You used `--password-fd 3` under `sudo`. Use `--password-fd 0` and feed the password on standard input.

**"… is already open (/dev/loopN)"**
The file is attached to a loop device. `ironykeys status <vault>` shows whether IronyKeys or another tool opened it.

**`close` says the mountpoint is in use**
Find what holds it with `sudo lsof +f -- ~/IronyKeys/<name>` or `fuser -vm ~/IronyKeys/<name>`. A shell that has `cd`'d into the directory counts.

**"the password is right but the vault holds no filesystem"**
The vault was created with `--fs none`. Format it through VeraCrypt or `cryptsetup` plus `mkfs`, or create a new vault with a filesystem.

**"one header is good and one is not"**
The vault still opens. Close it if open and run `ironykeys header-restore ~/vaults/keys.vc` to repair the damaged header from the intact one.

**After a reboot or power cut**
Mappings and state files do not survive a reboot; the vault is simply closed. Run `ironykeys verify` and open it again. If the power went while you were writing, the filesystem inside may need a check, as with any disk.

**A mapping is left behind after a crash**
```bash
sudo dmsetup ls | grep ironykeys
sudo umount ~/IronyKeys/<name>             # if still mounted
sudo dmsetup remove --retry ironykeys-<name>
sudo losetup -j ~/vaults/keys.vc           # shows the loop device
sudo losetup -d /dev/loopN
sudo rm /run/ironykeys/<name>.json
```

---

## 🧪 Testing

```bash
make test       # unit tests
make interop    # root-only tests against VeraCrypt and cryptsetup
```

The unit tests include a known-answer test: `testdata/ref-aes-sha512.vc` is a `4 MiB` volume created by VeraCrypt 1.26.31 with the published throwaway password `ironykeys-test-vector`. IronyKeys must parse its headers and decrypt a known text pattern from its data area.

The interop tests need the `veracrypt` command-line program and `cryptsetup`. They check, for `exFAT` and `ext4`, with and without a PIM:

- IronyKeys creates and formats a vault; VeraCrypt mounts it and reads and writes files; IronyKeys reads them back.
- VeraCrypt creates and formats a vault; IronyKeys opens it.
- `cryptsetup` reports the same header fields and filesystem.
- Failure cases: a second open, a busy mountpoint on close, a destroyed primary header, a read-only open, an unformatted vault, a non-empty mountpoint.

---

## 📂 Project layout

```text
cmd/ironykeys/        command-line entry point
internal/kdf/         PBKDF2-SHA512 and PIM handling
internal/header/      the 512-byte header: parse, build, encrypt, decrypt
internal/volume/      file layout, create, verify, open
internal/session/     loop device, dm-crypt mapping, mkfs, mount, state
internal/interop/     root-only tests against VeraCrypt and cryptsetup
testdata/             reference volume made by VeraCrypt
tools/                the Python script used to confirm the format
SPEC.md               format, commands, test plan, milestones
```

---

## ⚖️ Licence

MIT, see [LICENSE](LICENSE).

IronyKeys is an independent project. It is not affiliated with or endorsed by VeraCrypt or IDRIX, and contains no VeraCrypt or TrueCrypt code. It is also unrelated to the IronKey line of encrypted USB drives.
