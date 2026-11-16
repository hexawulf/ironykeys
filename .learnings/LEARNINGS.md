# Learnings

## [LRN-20261116-001] sudo + Go: an fd above 2 is silently replaced

- Context: `sudo ironykeys create v.vc --password-fd 3 3<<<secret`
- What happened: the vault was created and opened fine, but with the
  password `max 100000`, not `secret`.
- Cause: sudo (sudo-rs and classic sudo) closes every descriptor above 2.
  The Go runtime (1.25+) then opens the cgroup `cpu.max` file for its
  GOMAXPROCS logic and keeps it open, so it becomes fd 3. Reading "fd 3"
  succeeds and returns that file's contents.
- Fix: `checkPasswordFD` in cmd/ironykeys/main.go accepts only a pipe, a
  socket, or a regular file not under /sys or /proc. Under sudo use
  `--password-fd 0`.
- General rule: a program that takes an fd number from the command line must
  check what the descriptor is, not only that it is open.

## [LRN-20261116-002] dmsetup remove right after mkfs fails as busy

- udev still has the new device open for a moment after mkfs or umount.
- Fix: `dmsetup remove --retry`.
- A failed remove leaves a mapping that still holds the master key, so a
  failure here must never be ignored.

## [LRN-20261116-003] xts.NewCipher accepts 32-byte keys

- `golang.org/x/crypto/xts` with a 32-byte key gives AES-128-XTS without an
  error. Check for exactly 64 bytes before calling it.
