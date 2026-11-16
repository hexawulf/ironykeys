#!/usr/bin/env python3
# Author: 0xWulf | Modified: 2026-11-16
# M0: decrypt and print a VeraCrypt header (AES-XTS, PBKDF2-SHA512) and
# compare it with SPEC.md section 3. Test vectors only; password on argv.
import sys, hashlib, struct, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

path, password = sys.argv[1], sys.argv[2].encode()
iters = int(sys.argv[3]) if len(sys.argv) > 3 else 500000
data = open(path, 'rb').read()
S = len(data)

def xts(key, tweak_sector, buf, enc=False):
    c = Cipher(algorithms.AES(key), modes.XTS(tweak_sector.to_bytes(16, 'little')))
    o = c.encryptor() if enc else c.decryptor()
    return o.update(buf) + o.finalize()

def parse(off, label):
    h = data[off:off + 512]
    salt = h[:64]
    hk = hashlib.pbkdf2_hmac('sha512', password, salt, iters, 64)
    d = xts(hk, 0, h[64:])           # decrypted bytes 64..511 -> d[0..447]
    full = salt + d
    print(f"== {label} header @ {off}")
    print("  magic          ", full[64:68])
    if full[64:68] != b'VERA':
        print("  !! magic mismatch"); return None
    ver, minver = struct.unpack('>HH', full[68:72])
    crc_keys, = struct.unpack('>I', full[72:76])
    hidden, volsize, mkoff, encsize = struct.unpack('>QQQQ', full[92:124])
    flags, secsize = struct.unpack('>II', full[124:132])
    crc_hdr, = struct.unpack('>I', full[252:256])
    print(f"  header version  {ver}")
    print(f"  min prog ver    0x{minver:04X}")
    print(f"  reserved 76..91 zero: {full[76:92] == bytes(16)}")
    print(f"  hidden size     {hidden}")
    print(f"  volume size     {volsize}  (S-262144 = {S-262144})")
    print(f"  mk scope offset {mkoff}")
    print(f"  enc area size   {encsize}")
    print(f"  flags           {flags}")
    print(f"  sector size     {secsize}")
    print(f"  reserved 132..251 zero: {full[132:252] == bytes(120)}")
    print(f"  crc keys  stored {crc_keys:08x} calc {zlib.crc32(full[256:512]):08x}")
    print(f"  crc hdr   stored {crc_hdr:08x} calc {zlib.crc32(full[64:252]):08x}")
    print(f"  key area 320..511 all zero: {full[320:512] == bytes(192)}")
    return full[256:320]

mk = parse(0, "primary")
mkb = parse(S - 131072, "backup")
print("master keys equal (primary vs backup):", mk == mkb)
print("salts differ:", data[:64] != data[S-131072:S-131072+64])
# data area: decrypt first sectors with tweak = absolute sector number (256)
if mk:
    for tweak in (256, 0):
        pt = xts(mk, tweak, data[131072:131072 + 512])
        print(f"data sector 0, tweak {tweak}: all-zero plaintext = {pt == bytes(512)}  head={pt[:8].hex()}")
    pt = xts(mk, 257, data[131072 + 512:131072 + 1024])
    print(f"data sector 1, tweak 257: all-zero plaintext = {pt == bytes(512)}")
