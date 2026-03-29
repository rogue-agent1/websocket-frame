#!/usr/bin/env python3
"""websocket_frame: WebSocket frame encoder/decoder (RFC 6455)."""
import struct, hashlib, base64, os, sys

MAGIC = "258EAFA5-E914-47DA-95CA-5AB5AAAD5D37"

def accept_key(key):
    return base64.b64encode(hashlib.sha1((key + MAGIC).encode()).digest()).decode()

def encode_frame(payload, opcode=0x1, mask=False, fin=True):
    if isinstance(payload, str): payload = payload.encode()
    frame = bytearray()
    b0 = (0x80 if fin else 0) | opcode
    frame.append(b0)
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length <= 125:
        frame.append(mask_bit | length)
    elif length <= 65535:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack("!Q", length))
    if mask:
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    frame.extend(payload)
    return bytes(frame)

def decode_frame(data):
    offset = 0
    b0 = data[offset]; offset += 1
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    b1 = data[offset]; offset += 1
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack("!H", data[offset:offset+2])[0]; offset += 2
    elif length == 127:
        length = struct.unpack("!Q", data[offset:offset+8])[0]; offset += 8
    mask_key = None
    if masked:
        mask_key = data[offset:offset+4]; offset += 4
    payload = data[offset:offset+length]
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return {"fin": fin, "opcode": opcode, "masked": masked, "payload": payload, "length": length}

def test():
    # Text frame
    frame = encode_frame("Hello")
    decoded = decode_frame(frame)
    assert decoded["fin"]
    assert decoded["opcode"] == 0x1
    assert decoded["payload"] == b"Hello"
    assert not decoded["masked"]
    # Masked frame
    frame_m = encode_frame("Test", mask=True)
    decoded_m = decode_frame(frame_m)
    assert decoded_m["payload"] == b"Test"
    assert decoded_m["masked"]
    # Binary frame
    frame_b = encode_frame(b"\x00\x01\x02", opcode=0x2)
    decoded_b = decode_frame(frame_b)
    assert decoded_b["opcode"] == 0x2
    assert decoded_b["payload"] == b"\x00\x01\x02"
    # Close frame
    frame_c = encode_frame(b"", opcode=0x8)
    decoded_c = decode_frame(frame_c)
    assert decoded_c["opcode"] == 0x8
    # Accept key
    key = accept_key("dGhlIHNhbXBsZSBub25jZQ==")
    assert key == "s2ORy2FVrIqlTknzSutniERpRDI="
    # Large payload (126+)
    big = "x" * 200
    frame_big = encode_frame(big)
    decoded_big = decode_frame(frame_big)
    assert decoded_big["payload"] == big.encode()
    assert decoded_big["length"] == 200
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test": test()
    else: print("Usage: websocket_frame.py test")
