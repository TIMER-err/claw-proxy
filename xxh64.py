"""Pure-Python XXH64 (standard xxhash), verified byte-exact against the
`xxhash` library over inputs of length 0..300 with seed 0x6E52736AC806831E.
Used for Anthropic Claude Code CCH signing (CLIProxyAPI-compatible)."""

PRIME1 = 0x9E3779B185EBCA87
PRIME2 = 0xC2B2AE3D27D4EB4F
PRIME3 = 0x165667B19E3779F9
PRIME4 = 0x85EBCA77C2B2AE63
PRIME5 = 0x27D4EB2F165667C5
MASK = 0xFFFFFFFFFFFFFFFF


def _rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK


def _round(acc, lane):
    acc = (acc + (lane * PRIME2 & MASK)) & MASK
    acc = _rotl(acc, 31)
    return (acc * PRIME1) & MASK


def _merge(h, v):
    h ^= _round(0, v)
    h = (h * PRIME1) & MASK
    return (h + PRIME4) & MASK


def xxh64(data: bytes, seed: int = 0) -> int:
    length = len(data)
    idx = 0
    if length >= 32:
        v1 = (seed + PRIME1 + PRIME2) & MASK
        v2 = (seed + PRIME2) & MASK
        v3 = seed & MASK
        v4 = (seed - PRIME1) & MASK
        while idx + 32 <= length:
            v1 = _round(v1, int.from_bytes(data[idx:idx + 8], "little")); idx += 8
            v2 = _round(v2, int.from_bytes(data[idx:idx + 8], "little")); idx += 8
            v3 = _round(v3, int.from_bytes(data[idx:idx + 8], "little")); idx += 8
            v4 = _round(v4, int.from_bytes(data[idx:idx + 8], "little")); idx += 8
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & MASK
        h = _merge(h, v1); h = _merge(h, v2); h = _merge(h, v3); h = _merge(h, v4)
    else:
        h = (seed + PRIME5) & MASK

    h = (h + length) & MASK

    while idx + 8 <= length:
        k1 = (int.from_bytes(data[idx:idx + 8], "little") * PRIME2) & MASK
        h ^= _rotl(k1, 31) * PRIME1 & MASK
        h = (_rotl(h, 27) * PRIME1 + PRIME4) & MASK
        idx += 8

    if idx + 4 <= length:
        h ^= int.from_bytes(data[idx:idx + 4], "little") * PRIME1 & MASK
        h = (_rotl(h, 23) * PRIME2 + PRIME3) & MASK
        idx += 4

    while idx < length:
        h ^= data[idx] * PRIME5 & MASK
        h = _rotl(h, 11) * PRIME1 & MASK
        idx += 1

    h ^= h >> 33
    h = (h * PRIME2) & MASK
    h ^= h >> 29
    h = (h * PRIME3) & MASK
    h ^= h >> 32
    return h & MASK


if __name__ == "__main__":
    import sys
    try:
        import xxhash as _ref
    except ImportError:
        print("install xxhash to verify; self-test skipped")
        sys.exit(0)
    ok = True
    for L in range(0, 300):
        data = bytes(range(L % 256)) if L < 256 else (b"x" * L)
        if xxh64(data, 0x6E52736AC806831E) != _ref.xxh64(data, seed=0x6E52736AC806831E).intdigest():
            ok = False
            print("FAIL", L)
    print("ALL OK" if ok else "FAILS")
    sys.exit(0 if ok else 1)
