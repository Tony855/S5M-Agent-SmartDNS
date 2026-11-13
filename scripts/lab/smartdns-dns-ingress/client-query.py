#!/usr/bin/env python3
import socket, struct, sys, time
HOST, PORT, NAME, EXPECTED, TRANSPORT = "172.31.0.10", 6055, sys.argv[1], sys.argv[2], sys.argv[3]
QID = b"\x5a\xa5"
QNAME = b"".join(bytes([len(x)]) + x.encode() for x in NAME.split(".")) + b"\0"
QUESTION = QID + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + QNAME + b"\x00\x01\x00\x01"
def parse(packet):
    if len(packet)<12 or packet[:2]!=QID: raise ValueError("invalid DNS header")
    qd, an = struct.unpack("!HH",packet[4:8])
    if qd!=1: raise ValueError(f"unexpected question count {qd}")
    off=12
    while off<len(packet) and packet[off]!=0:
        n=packet[off]
        if n&0xc0: raise ValueError("compressed question")
        off += n+1
    off += 5
    out=[]
    for _ in range(an):
        if off+2>len(packet): raise ValueError("truncated answer name")
        if packet[off]&0xc0==0xc0: off+=2
        else:
            while off<len(packet) and packet[off]!=0: off+=packet[off]+1
            off+=1
        if off+10>len(packet): raise ValueError("truncated RR")
        typ, cls, ttl, size=struct.unpack("!HHIH",packet[off:off+10]); off+=10
        data=packet[off:off+size]; off+=size
        if typ==1 and cls==1 and size==4: out.append(socket.inet_ntoa(data))
    return out
def exchange():
    if TRANSPORT=="udp":
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(1); s.sendto(QUESTION,(HOST,PORT)); return s.recvfrom(4096)[0]
    with socket.create_connection((HOST,PORT),timeout=1) as s:
        s.settimeout(1); s.sendall(struct.pack("!H",len(QUESTION))+QUESTION)
        h=s.recv(2)
        if len(h)!=2: raise ValueError("missing TCP length")
        n=struct.unpack("!H",h)[0]; data=bytearray()
        while len(data)<n:
            chunk=s.recv(n-len(data))
            if not chunk: raise ValueError("truncated TCP reply")
            data.extend(chunk)
        return bytes(data)
error=None
for _ in range(20):
    try:
        got=parse(exchange())
        if EXPECTED=="NONE" and len(got)==0:
            print(f"PASS {TRANSPORT} {NAME} returned no A answer for an unmapped client"); sys.exit(0)
        if got==[EXPECTED]:
            print(f"PASS {TRANSPORT} {NAME} -> {EXPECTED}"); sys.exit(0)
        error=f"unexpected answers {got!r}"
    except Exception as e: error=str(e)
    time.sleep(.25)
print(f"FAIL {TRANSPORT} {NAME}: {error}",file=sys.stderr); sys.exit(1)
