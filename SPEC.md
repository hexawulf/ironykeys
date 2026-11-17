# IronyKeys — Specification (v0.2)

- Author: 0xWulf
- Drafted: 2026-11-16
- Status: IMPLEMENTED (v0.2)

IronyKeys is a small command-line tool for Raspberry Pi and other Linux hosts
that creates and opens a single fixed-size encrypted vault file. The vault uses
the VeraCrypt volume format, so the official VeraCrypt and `cryptsetup` can
open it too. The name is for the irony of keeping PGP and SSH keys in a vault
that is backed up to the cloud.

## 1. Goals and non-goals

### Goals
1. One vault = one file of a fixed size chosen at creation (default 256 MiB).
   The file never grows or shrinks and reveals nothing about how full it is.
2. Byte-compatible with the VeraCrypt format: a vault made by IronyKeys opens
   in VeraCrypt (Linux, Windows, macOS) and in `cryptsetup --type tcrypt
   --veracrypt`, and a matching VeraCrypt-made vault opens in IronyKeys.
3. No cryptographic primitives of our own. Key derivation and the header
   cipher come from Go's maintained libraries; bulk encryption is done by the
   Linux kernel (dm-crypt).
4. One static binary for arm64 and amd64, no runtime dependencies beyond
   standard system tools.
5. Safe to script: clear exit codes, a dry-run for anything destructive, and
   the password is never taken from the command line.

### Non-goals (v0.x)
- Hidden volumes, cipher cascades, keyfiles, security tokens.
- System / boot encryption, in-place encryption of existing partitions.
- Ciphers other than AES; hashes other than SHA-512.
- Legacy TrueCrypt volumes.
- Windows or macOS builds of IronyKeys itself (use VeraCrypt there).
- A GUI or web interface.
- A Docker image (deferred, see section 6).
- Tamper detection inside the format. XTS keeps data secret but does not
  detect modification; integrity is handled outside the vault (section 8).

## 2. Supported profile

IronyKeys reads and writes exactly one profile of the VeraCrypt format:

| Property | Value |
|---|---|
| Volume type | Normal (non-hidden), file-hosted |
| Cipher | AES-256 in XTS mode |
| Key derivation | PBKDF2-HMAC-SHA512 |
| Iterations | 500,000 by default; `15000 + PIM * 1000` when a PIM is given |
| Derived header key | 64 bytes (two 256-bit XTS keys) |
| Salt | 64 bytes, random |
| Sector size | 512 bytes |
| Password | UTF-8, 1–128 bytes |
| Inner filesystem | exFAT (default) or ext4 |

A volume outside this profile is rejected with a clear message
("not an IronyKeys-profile volume; open it with VeraCrypt").

## 3. On-disk format

All multi-byte integers are big-endian. `S` is the file size in bytes.
`S` must be a multiple of 512 and at least 1 MiB (enforced minimum for
IronyKeys: 4 MiB).

### 3.1 File layout

| Offset | Size | Contents |
|---|---|---|
| 0 | 65,536 | Primary header area. First 512 bytes are the header; the rest is random. |
| 65,536 | 65,536 | Hidden-volume header area. Unused: random bytes. |
| 131,072 | S − 262,144 | Data area (encrypted filesystem). |
| S − 131,072 | 65,536 | Backup header area. Same fields as primary, different salt. |
| S − 65,536 | 65,536 | Backup hidden-volume header area. Unused: random bytes. |

### 3.2 Header (512 bytes)

Bytes 0–63 are stored in the clear. Bytes 64–511 (448 bytes) are encrypted
with AES-256-XTS under the header key, as one data unit with tweak 0.

| Offset | Size | Field | Value written by IronyKeys |
|---|---|---|---|
| 0 | 64 | Salt | random |
| 64 | 4 | Magic | ASCII `VERA` |
| 68 | 2 | Header format version | 5 |
| 70 | 2 | Minimum program version | 0x010B |
| 72 | 4 | CRC-32 of decrypted bytes 256–511 | computed |
| 76 | 16 | Reserved | zero |
| 92 | 8 | Hidden volume size | 0 |
| 100 | 8 | Volume (data area) size | S − 262,144 |
| 108 | 8 | Master-key scope offset | 131,072 |
| 116 | 8 | Encrypted area size | S − 262,144 |
| 124 | 4 | Flags | 0 |
| 128 | 4 | Sector size | 512 |
| 132 | 120 | Reserved | zero |
| 252 | 4 | CRC-32 of decrypted bytes 64–251 | computed |
| 256 | 64 | Master key (two 256-bit XTS keys) | random |
| 320 | 192 | Rest of key area | zero |

CRC-32 is the standard IEEE polynomial (same as zlib).

Every field above was confirmed in M0 (2026-11-16) against a volume created
by VeraCrypt 1.26.31: decrypted independently with `tools/m0_header_check.py`
and cross-checked with `cryptsetup tcryptDump`. One correction came out of it:
the unused part of the key area (320–511) is zero, not random.

Reference fixture: `testdata/ref-aes-sha512.vc` (4 MiB, no filesystem,
password `ironykeys-test-vector`, default PIM). Data sector 0 holds the ASCII
pattern `IRONYKEYS-M0-PLAINTEXT-SECTOR-0!` repeated 16 times; sector 1 is
zeros. SHA-256 `50187622573e5a8cefd618e551c270585a965e8ab4ad24de6e91559606dc27f9`.

### 3.3 Opening a volume

1. Read 512 bytes at offset 0. Derive the header key from password + salt.
2. Decrypt bytes 64–511. Accept only if the magic is `VERA` and both CRCs
   match.
3. If that fails, repeat with the backup header at `S − 131,072`. If the
   backup works, open the vault and warn that the primary header is damaged.
4. If both fail: "wrong password or not a VeraCrypt volume" (the two cases
   cannot be told apart, by design).
5. Check the header fields against the profile in section 2.

### 3.4 Data area

AES-256-XTS, 512-byte sectors. The tweak for a sector is its sector number
counted from the start of the file, so the first data sector uses 256.
The matching device-mapper table (confirmed in M0: this is the table
`cryptsetup` builds, and known plaintext written through it decrypts
independently with tweak 256) is:

```
0 <data_sectors> crypt aes-xts-plain64 <master_key_hex> 256 <loop_device> 256
```

## 4. Commands

```
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

A vault's name defaults to its file name without the extension
(`IronyKeys.vc` → `IronyKeys`); `--name` overrides it. The name is used for
the mapping (`/dev/mapper/ironykeys-<name>`), the default mountpoint and
`close`.

| Command | What it does | Needs root |
|---|---|---|
| `create` | Writes a new vault: random-fills the whole file, writes primary and backup headers, then formats the inner filesystem. Refuses to overwrite an existing file. | Only for the format step (`--fs none` needs no root) |
| `open` | Checks the password, attaches a loop device, creates the dm-crypt mapping `ironykeys-<name>`, mounts it. | Yes |
| `close` | Unmounts, removes the mapping, detaches the loop device. | Yes |
| `status` | Lists open vaults. With `--quiet` prints nothing and only sets the exit code, for use by backup scripts. | No |
| `verify` | Checks the password against both headers and reports each one's state. Never mounts. | No |
| `passwd` | Changes the vault password (or PIM) by re-encrypting both headers with fresh random salts; the master key and data area are untouched. Refuses to run on an open vault. | No |
| `header-restore` | Rewrites a damaged primary or backup header from the intact one using a fresh random salt. Refuses to run on an open vault. | No |
| `info` | Prints what is knowable without the password: size, sector alignment, whether the vault is open. | No |

### 4.1 Password handling
- Prompted on the terminal with echo off. `create` asks twice.
- `--password-fd N` reads it from a file descriptor, for automation.
- Under `sudo` only descriptor 0 survives (sudo closes the rest), so the
  form there is `sudo ironykeys open <vault> --password-fd 0 <<<"$PW"`.
  IronyKeys refuses a descriptor the caller did not pass. Without this
  check the number is reused by a file the Go runtime opens for itself, and
  a vault would be created with a password nobody chose (found in M3).
- There is no `--password` flag and no environment variable, so the password
  cannot leak through `ps`, shell history or `/proc/*/environ`.

### 4.2 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`status --quiet`: vault is closed) |
| 1 | General error |
| 2 | Usage error |
| 3 | Wrong password or not a VeraCrypt volume |
| 4 | Vault is open / busy (`status --quiet`: vault is open) |
| 5 | Volume is valid VeraCrypt but outside the supported profile |
| 6 | `verify` only: one of the two headers is damaged; the other is good |

`open` on a vault with one damaged header succeeds with exit 0 and prints a
warning. `status <vault>` without `--quiet` also exits 4 when the vault is
open.

### 4.3 Mount defaults
- Mountpoint: `/home/<user>/IronyKeys/<name>` unless given.
- Options: `nodev,nosuid,noexec`; for exFAT also `uid`, `gid` of the invoking
  user and `umask=077`.
- An existing mountpoint must be an empty directory with nothing mounted on
  it. A mountpoint that `open` created is removed again by `close`.
- Runtime state in `/run/ironykeys/<name>.json` (loop device, mapping,
  mountpoint; no secrets). It disappears on reboot, like the mapping.
- "Open" is detected from the kernel: a vault is open if any loop device is
  backed by the file. This also catches a vault opened by VeraCrypt or
  cryptsetup, and needs no root, so `status` and backup scripts can use it.
- ext4 vaults are created with the root directory owned by the invoking
  user, mode 700.

## 5. Architecture

Language: Go, one module, static build (`CGO_ENABLED=0`).

```
cmd/ironykeys/        command-line entry point
internal/header/      parse, build, encrypt, decrypt the 512-byte header
internal/kdf/         PBKDF2-SHA512 with PIM handling
internal/volume/      file layout, create, verify, backup-header fallback
internal/session/     loop device, dm-crypt mapping, mkfs, mount, state file
internal/interop/     root-only tests against VeraCrypt and cryptsetup
```

Dependencies: `golang.org/x/crypto` (xts), `golang.org/x/term`,
`golang.org/x/sys`. PBKDF2 comes from Go's standard library. Nothing else.

Kernel interface, v0.1: call `losetup` and `dmsetup`, passing the table (with
the key) on stdin so the key never appears in a process list. A later version
may talk to the loop and device-mapper ioctls directly and drop both tools.

Key hygiene is best effort: key buffers are zeroed after use and the process
locks its memory (`mlockall`) where permitted. Go cannot guarantee that no
copy survives in memory; this is stated in the README rather than hidden.

## 6. Docker (deferred)

Not part of v0.x. Decided 2026-11-16: the plain binary is the only supported
way to run IronyKeys for now.

Notes kept for a later revisit:
- `open`, `close` and formatting use the host kernel, so a container would
  need `--privileged` and `-v /dev:/dev`. It would be packaging, not isolation.
- Only `create --fs none`, `verify` and `info` could run unprivileged.
- Not every target host runs Docker, so an image would not cover them all.

## 7. Testing

### 7.1 Unit tests (no root, run in CI on arm64 and amd64)
- Header build → encrypt → decrypt → parse round trip.
- Known-answer test: a small reference vault created by official VeraCrypt
  with a published throwaway password is committed as a fixture; IronyKeys
  must parse it and recover the expected field values.
- Wrong password, flipped bit in each CRC region, bad magic, truncated file.
- PIM iteration arithmetic.

### 7.2 Interoperability matrix (root, loop + dm-crypt)

| Created by | Opened by | Check |
|---|---|---|
| IronyKeys | VeraCrypt 1.26.31 console | mounts, files readable |
| IronyKeys | `cryptsetup open --type tcrypt --veracrypt` | mounts, files readable |
| IronyKeys | `cryptsetup tcryptDump` | reported fields match section 3 |
| VeraCrypt | IronyKeys | mounts, files readable |
| IronyKeys | IronyKeys | write files, close, reopen, checksums match |

Each row runs for exFAT and ext4, with and without a PIM.

Run it with:

```
go test -c -tags interop -o interop.test ./internal/interop
sudo ./interop.test -test.v
```

### 7.3 Failure tests
- Primary header overwritten with random bytes → opens via backup, exit 6.
- Both headers destroyed → exit 3, nothing mounted.
- `open` on an already-open vault → exit 4.
- `create` onto an existing path → refuses.
- `close` with a busy mountpoint → fails cleanly, mapping stays intact.
- Interrupted `create` leaves no file that passes `verify`.

## 8. Backups and integrity

- Backups copy the closed vault file. The backup script calls
  `ironykeys status --quiet <vault>` first and skips the run on exit 4.
- Each snapshot gets a SHA-256 sidecar file, checked on restore. This covers
  the tamper detection that XTS does not provide.
- A restore test means: download a snapshot to a second host, check the
  SHA-256, run `ironykeys verify`, open it, compare a file listing.
- Any existing key store and its backups stay in place until a
  restore test of IronyKeys has passed on a second machine.

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | Reference vault + field check | DONE 2026-11-16. All fields confirmed; one correction (key area padding is zero) |
| M1 | `verify`, `info` | DONE 2026-11-16. Reads the VeraCrypt-made fixture; unit tests pass |
| M2 | `create` (unformatted vault) | DONE 2026-11-16. VeraCrypt 1.26.31 and cryptsetup 2.8.4 open the result and read each other's writes, with and without a PIM |
| M3 | `open`, `close`, `status`, formatting | DONE 2026-11-16. Interop matrix (exFAT and ext4, with and without PIM, both directions) and failure tests pass on a Raspberry Pi (arm64, Ubuntu 26.04) |
| M4 | Release | DONE 2026-11-17. Tagged `v0.1.0` with `arm64` and `amd64` binaries |
| M5 | Real use | DONE 2026-11-17. Real vault created, backed up, and deployed on `piapps2` and `linuxsvr` |
| M6 | v0.2 (`passwd`, `header-restore`) | DONE 2026-11-17. In-place password/PIM change and header repair implemented and tested |

## 10. Open decisions

1. Repository: `github.com/hexawulf/ironykeys`. Public or private is still open.
2. Licence: MIT (no VeraCrypt code is used).
3. Decided 2026-11-16: exFAT is the default inner filesystem, for Windows
   and macOS compatibility; ext4 stays available with `--fs ext4`.
4. Decided 2026-11-16: Go 1.26 from Ubuntu's packages.
