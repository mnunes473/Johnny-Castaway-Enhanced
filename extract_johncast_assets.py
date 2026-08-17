#!/usr/bin/env python3
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

JOHNCAST_URL = "https://www.nic.funet.fi/pub/msdos/Mirrors/winsite/win95/desktop/johncast.exe"
JOHNCAST_SHA256 = "a8bb0c15e37b63bdb30fd66e80b1ed01f73bacc5e9133d94c7ea59bb31b271da"
MAXBITS = 13

LITLEN = [
    11,124,8,7,28,7,188,13,76,4,10,8,12,10,12,10,8,23,8,9,7,6,7,8,7,6,
    55,8,23,24,12,11,7,9,11,12,6,7,22,5,7,24,6,11,9,6,7,22,7,11,38,7,9,
    8,25,11,8,11,9,12,8,12,5,38,5,38,5,11,7,5,6,21,6,10,53,8,7,24,10,
    27,44,253,253,253,252,252,252,13,12,45,12,45,12,61,12,45,44,173
]
LENLEN = [2,35,36,53,38,23]
DISTLEN = [2,20,53,230,247,151,248]
BASE = [3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264]
EXTRA = [0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8]

def construct(rep):
    lengths = []
    for val in rep:
        lengths.extend([val & 15] * ((val >> 4) + 1))
    count = [0] * (MAXBITS + 1)
    for n in lengths:
        count[n] += 1
    offs = [0] * (MAXBITS + 1)
    for n in range(1, MAXBITS):
        offs[n + 1] = offs[n] + count[n]
    symbol = [0] * sum(count[1:])
    next_offs = offs[:]
    for sym, n in enumerate(lengths):
        if n:
            symbol[next_offs[n]] = sym
            next_offs[n] += 1
    return count, symbol

LITCODE = construct(LITLEN)
LENCODE = construct(LENLEN)
DISTCODE = construct(DISTLEN)

class Bits:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bitbuf = 0
        self.bitcnt = 0

    def bits(self, need):
        val = self.bitbuf
        while self.bitcnt < need:
            if self.pos >= len(self.data):
                raise EOFError("Unexpected end of compressed stream")
            val |= self.data[self.pos] << self.bitcnt
            self.pos += 1
            self.bitcnt += 8
        self.bitbuf = val >> need
        self.bitcnt -= need
        return val & ((1 << need) - 1) if need else 0

    def decode(self, table):
        count, symbol = table
        code = first = index = 0
        for length in range(1, MAXBITS + 1):
            code |= self.bits(1) ^ 1
            n = count[length]
            if code < first + n:
                return symbol[index + code - first]
            index += n
            first = (first + n) << 1
            code <<= 1
        raise ValueError("Invalid Huffman code")

def dcl_implode_decode(src):
    s = Bits(src)
    lit = s.bits(8)
    dictionary = s.bits(8)
    if lit > 1 or dictionary < 4 or dictionary > 6:
        raise ValueError("Invalid PKWARE DCL stream header")
    out = bytearray()
    while True:
        if s.bits(1):
            symbol = s.decode(LENCODE)
            length = BASE[symbol] + s.bits(EXTRA[symbol])
            if length == 519:
                break
            dbits = 2 if length == 2 else dictionary
            distance = (s.decode(DISTCODE) << dbits) + s.bits(dbits) + 1
            if distance > len(out):
                raise ValueError("Invalid back-reference")
            for _ in range(length):
                out.append(out[-distance])
        else:
            out.append(s.decode(LITCODE) if lit else s.bits(8))
    return bytes(out)

def main():
    print("Downloading original Johnny Castaway package...")
    with urllib.request.urlopen(JOHNCAST_URL, timeout=60) as response:
        package = response.read()

    sha256 = hashlib.sha256(package).hexdigest()
    print("johncast.exe SHA-256:", sha256)
    if sha256.lower() != JOHNCAST_SHA256:
        raise SystemExit("ERROR: johncast.exe SHA-256 does not match trusted reference")

    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        resource_map = zf.read("RESOURCE.MAP")
        tscomp = zf.read("RESOURCE.00$")

    # TSComp v1.3 single-file header:
    # offset 0x0e = compressed size, filename at 0x1d, compressed stream follows.
    fn_len = tscomp[0x1c]
    compressed_offset = 0x1d + fn_len + 1
    compressed_size = int.from_bytes(tscomp[0x0e:0x12], "little")
    compressed = tscomp[compressed_offset:compressed_offset + compressed_size]

    resource_001 = dcl_implode_decode(compressed)

    if len(resource_map) != 1461:
        raise SystemExit(f"ERROR: Unexpected RESOURCE.MAP size: {len(resource_map)}")
    if len(resource_001) != 1175645:
        raise SystemExit(f"ERROR: Unexpected RESOURCE.001 size: {len(resource_001)}")

    os.makedirs("assets", exist_ok=True)
    with open("assets/RESOURCE.MAP", "wb") as f:
        f.write(resource_map)
    with open("assets/RESOURCE.001", "wb") as f:
        f.write(resource_001)

    print("Extracted assets/RESOURCE.MAP:", len(resource_map), "bytes")
    print("Extracted assets/RESOURCE.001:", len(resource_001), "bytes")
    print("RESOURCE.MAP SHA-256:", hashlib.sha256(resource_map).hexdigest())
    print("RESOURCE.001 SHA-256:", hashlib.sha256(resource_001).hexdigest())

if __name__ == "__main__":
    main()
