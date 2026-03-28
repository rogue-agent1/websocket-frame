#!/usr/bin/env python3
"""WebSocket frame encoder/decoder."""
import sys,struct,os,hashlib,base64
def encode_frame(payload,opcode=1,mask=True):
    if isinstance(payload,str): payload=payload.encode()
    frame=bytearray()
    frame.append(0x80|opcode)  # FIN + opcode
    length=len(payload)
    mask_bit=0x80 if mask else 0
    if length<126: frame.append(mask_bit|length)
    elif length<65536: frame.append(mask_bit|126);frame.extend(struct.pack(">H",length))
    else: frame.append(mask_bit|127);frame.extend(struct.pack(">Q",length))
    if mask:
        mask_key=os.urandom(4);frame.extend(mask_key)
        payload=bytes(b^mask_key[i%4] for i,b in enumerate(payload))
    frame.extend(payload)
    return bytes(frame)
def decode_frame(data):
    i=0;fin=bool(data[i]&0x80);opcode=data[i]&0x0f;i+=1
    masked=bool(data[i]&0x80);length=data[i]&0x7f;i+=1
    if length==126: length=struct.unpack(">H",data[i:i+2])[0];i+=2
    elif length==127: length=struct.unpack(">Q",data[i:i+8])[0];i+=8
    mask_key=None
    if masked: mask_key=data[i:i+4];i+=4
    payload=data[i:i+length]
    if mask_key: payload=bytes(b^mask_key[j%4] for j,b in enumerate(payload))
    types={0:"continuation",1:"text",2:"binary",8:"close",9:"ping",10:"pong"}
    return {"fin":fin,"opcode":types.get(opcode,str(opcode)),"masked":masked,"length":length,"payload":payload}
def handshake_key(client_key):
    magic="258EAFA5-E914-47DA-95CA-5AB5DC11BE97"
    return base64.b64encode(hashlib.sha1((client_key+magic).encode()).digest()).decode()
def main():
    msg="Hello WebSocket!"
    frame=encode_frame(msg)
    print(f"Encoded: {len(frame)} bytes (message: {len(msg)} chars)")
    print(f"Hex: {frame[:20].hex()}...")
    decoded=decode_frame(frame)
    print(f"Decoded: opcode={decoded['opcode']}, fin={decoded['fin']}, payload='{decoded['payload'].decode()}'")
    key=handshake_key("dGhlIHNhbXBsZSBub25jZQ==")
    print(f"\nHandshake accept: {key}")
if __name__=="__main__": main()
