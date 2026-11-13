#!/usr/bin/env python3
import socket,sys
host,port=sys.argv[1],int(sys.argv[2])
q=(b"\x5a\xa5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x07example\x03com\x00\x00\x01\x00\x01")
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(4); s.sendto(q,(host,port)); r,_=s.recvfrom(4096)
    assert len(r)>=12 and r[:2]==q[:2]
print("PASS udp",flush=True)
with socket.create_connection((host,port),timeout=4) as s:
    s.sendall(len(q).to_bytes(2,"big")+q); h=s.recv(2); assert len(h)==2
    n=int.from_bytes(h,"big"); r=bytearray()
    while len(r)<n:
        x=s.recv(n-len(r))
        if not x:break
        r.extend(x)
    assert len(r)>=12 and r[:2]==q[:2]
print("PASS tcp",flush=True)
