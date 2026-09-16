
import base64
import hashlib
import lzma
import struct
import sys

HDR = 80
FILTERS = [{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,
            "dict_size": 1 << 26, "lc": 3, "lp": 0, "pb": 1}]


def split(raw):
    off = HDR
    while off < len(raw):
        (ln,) = struct.unpack_from(">I", raw, off)
        tag = raw[off + 4:off + 8]
        params = raw[off + 8:off + 10]
        payload = raw[off + 10:off + 10 + ln]
        crc = raw[off + 10 + ln:off + 14 + ln]
        yield ln, tag, params, payload, crc
        off += 14 + ln


def chain(seed, total):
    out = bytearray(seed)
    cur = seed
    while len(out) < total:
        cur = hashlib.sha256(cur).digest()
        out += cur
    return bytes(out[:total])


def is_chain(payload):
    return len(payload) % 32 == 0 and len(payload) >= 64 and \
        chain(payload[:32], len(payload)) == payload


def pack(raw):
    meta = bytearray()
    body = bytearray()
    n = 0
    for ln, tag, params, payload, crc in split(raw):
        n += 1
        flag = 1 if is_chain(payload) else 0
        meta += struct.pack(">IB", ln, flag) + tag + params + crc
        body += payload[:32] if flag else payload
    return struct.pack(">I", n) + raw[:HDR] + bytes(meta) + bytes(body)


def unpack(blob):
    (n,) = struct.unpack_from(">I", blob, 0)
    head = blob[4:4 + HDR]
    meta = blob[4 + HDR:4 + HDR + n * 15]
    body = blob[4 + HDR + n * 15:]
    out = bytearray(head)
    pos = 0
    for i in range(n):
        ln, flag = struct.unpack_from(">IB", meta, i * 15)
        tag = meta[i * 15 + 5:i * 15 + 9]
        params = meta[i * 15 + 9:i * 15 + 11]
        crc = meta[i * 15 + 11:i * 15 + 15]
        if flag:
            payload = chain(bytes(body[pos:pos + 32]), ln)
            pos += 32
        else:
            payload = bytes(body[pos:pos + ln])
            pos += ln
        out += struct.pack(">I", ln) + tag + params + payload + crc
    return bytes(out)


def compress(src, dst):
    with open(src, "rb") as f:
        text = f.read()
    try:
        raw = base64.b64decode(text)
        assert base64.b64encode(raw) == text
        packed = pack(raw)
        assert unpack(packed) == raw
        blob, mode = packed, b"\x02"
    except Exception:
        blob, mode = text, b"\x00"
    with open(dst, "wb") as f:
        f.write(mode + lzma.compress(blob, format=lzma.FORMAT_RAW,
                                     filters=FILTERS))


def decompress(src, dst):
    with open(src, "rb") as f:
        data = f.read()
    blob = lzma.decompress(data[1:], format=lzma.FORMAT_RAW, filters=FILTERS)
    out = base64.b64encode(unpack(blob)) if data[:1] == b"\x02" else blob
    with open(dst, "wb") as f:
        f.write(out)


def main(argv):
    if len(argv) != 3 or argv[0] not in ("--compress", "--decompress"):
        sys.stderr.write("usage: main.py --compress|--decompress <in> <out>\n")
        return 2
    (compress if argv[0] == "--compress" else decompress)(argv[1], argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
