# traffic.py PEER4 PEER6: the everyday traffic checks a rig machine makes to
# the other one over the rig link, over IPv4 and IPv6: an ssh banner, a TLS
# request, an SMTP banner, a DNS answer, and 1 MB through the p2p echo. One
# line per check, "name: ok" or "name: FAILED", sorted, nothing that varies
# from run to run. Exit 1 when one failed.
import os, socket, ssl, struct, sys

peer4, peer6 = sys.argv[1], sys.argv[2]
T = 5


def conn(addr, port):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(T)
    s.connect((addr, port))
    return s


def ssh(addr):
    with conn(addr, 22) as s:
        return s.recv(64).startswith(b"SSH-2.0")


def https(addr):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with conn(addr, 443) as s, ctx.wrap_socket(s) as t:
        t.sendall(b"GET / HTTP/1.1\r\nHost: rig.test\r\n\r\n")
        b = b""
        while True:
            part = t.recv(4096)
            if not part:
                break
            b += part
        return b.endswith(b"autopatch-rig https")


def smtp(addr):
    with conn(addr, 25) as s:
        ok = s.recv(64).startswith(b"220 ")
        s.sendall(b"QUIT\r\n")
        return ok and s.recv(64).startswith(b"221 ")


def dns(addr):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(T)
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rig\x04test\x00\x00\x01\x00\x01"
        s.sendto(q, (addr, 53))
        a, _ = s.recvfrom(512)
        return a[:2] == b"\x12\x34" and a[6:8] == b"\x00\x01"


def p2p(addr):
    data = os.urandom(1 << 20)
    with conn(addr, 26656) as s:
        s.sendall(struct.pack(">I", len(data)) + data)
        n = struct.unpack(">I", s.recv(4).rjust(4, b"\x00"))[0]
        b = b""
        while len(b) < n:
            part = s.recv(1 << 16)
            if not part:
                break
            b += part
        return b == data


lines, bad = [], False
for name, fn in [("ssh", ssh), ("https", https), ("smtp", smtp), ("dns", dns), ("p2p 1 MB", p2p)]:
    for fam, addr in [("IPv4", peer4), ("IPv6", peer6)]:
        try:
            ok = fn(addr)
        except Exception:
            ok = False
        lines.append("%s over %s: %s" % (name, fam, "ok" if ok else "FAILED"))
        bad = bad or not ok
print("\n".join(sorted(lines)))
sys.exit(1 if bad else 0)
