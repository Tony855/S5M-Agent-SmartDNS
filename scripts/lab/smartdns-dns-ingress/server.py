#!/usr/bin/env python3
import socket, threading
PORT=6055
def response(q):
    if len(q)<12: return b""
    return q[:2]+b"\x81\x80"+q[4:6]+b"\x00\x00\x00\x00\x00\x00"+q[12:]
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",PORT)); print("READY udp",flush=True)
    while True:
        q,p=s.recvfrom(4096); print(f"OBSERVED udp {p[0]}:{p[1]}",flush=True); r=response(q)
        if r: s.sendto(r,p)
def tcp_client(c,p):
    with c:
        h=c.recv(2)
        if len(h)!=2:return
        n=int.from_bytes(h,"big"); q=bytearray()
        while len(q)<n:
            x=c.recv(n-len(q))
            if not x:return
            q.extend(x)
        print(f"OBSERVED tcp {p[0]}:{p[1]}",flush=True); r=response(bytes(q))
        if r:c.sendall(len(r).to_bytes(2,"big")+r)
def tcp():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",PORT)); s.listen(32); print("READY tcp",flush=True)
    while True:
        c,p=s.accept(); threading.Thread(target=tcp_client,args=(c,p),daemon=True).start()
threading.Thread(target=udp,daemon=True).start(); tcp()
