#!/usr/bin/env python3
"""websocket_frame - WebSocket frame encoder/decoder (RFC 6455)."""
import sys, json, struct, hashlib, base64, os

def encode_frame(payload, opcode=1, mask=True, fin=True):
    if isinstance(payload, str): payload = payload.encode()
    frame = bytearray()
    first_byte = (0x80 if fin else 0) | (opcode & 0x0f)
    frame.append(first_byte)
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length <= 125: frame.append(mask_bit | length)
    elif length <= 65535: frame.append(mask_bit | 126); frame.extend(struct.pack(">H", length))
    else: frame.append(mask_bit | 127); frame.extend(struct.pack(">Q", length))
    if mask:
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        masked = bytearray(payload[i] ^ mask_key[i % 4] for i in range(length))
        frame.extend(masked)
    else:
        frame.extend(payload)
    return bytes(frame)

def decode_frame(data):
    pos = 0
    fin = bool(data[pos] & 0x80)
    opcode = data[pos] & 0x0f; pos += 1
    masked = bool(data[pos] & 0x80)
    length = data[pos] & 0x7f; pos += 1
    if length == 126: length = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
    elif length == 127: length = struct.unpack(">Q", data[pos:pos+8])[0]; pos += 8
    if masked:
        mask_key = data[pos:pos+4]; pos += 4
        payload = bytes(data[pos+i] ^ mask_key[i % 4] for i in range(length))
    else:
        payload = data[pos:pos+length]
    op_names = {0:"continuation",1:"text",2:"binary",8:"close",9:"ping",10:"pong"}
    return {"fin": fin, "opcode": op_names.get(opcode, str(opcode)), "masked": masked,
            "length": length, "payload": payload.decode(errors='replace') if opcode == 1 else payload.hex()}

def ws_accept_key(key):
    magic = "258EAFA5-E914-47DA-95CA-5AB5DC11D65B"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

def main():
    print("WebSocket frame demo\n")
    # Text frame
    frame = encode_frame("Hello, WebSocket!", opcode=1, mask=True)
    decoded = decode_frame(frame)
    print(f"  Text frame: {len(frame)} bytes")
    print(f"  Decoded: {json.dumps(decoded)}")
    # Binary frame
    bframe = encode_frame(b"\x00\x01\x02\x03", opcode=2, mask=False)
    bdecoded = decode_frame(bframe)
    print(f"  Binary frame: {json.dumps(bdecoded)}")
    # Ping/Pong
    ping = encode_frame("ping", opcode=9, mask=True)
    print(f"  Ping: {len(ping)} bytes")
    # Handshake key
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    accept = ws_accept_key(key)
    print(f"\n  Sec-WebSocket-Accept: {accept}")
    expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    print(f"  RFC match: {'✓' if accept == expected else '✗'}")

if __name__ == "__main__":
    main()
