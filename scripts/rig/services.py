# services.py SELF4 SELF6: the everyday services a rig machine runs for the
# traffic checks between the two rig VMs: TLS on 443, an SMTP banner on 25,
# an echo on 26656 (gno.land's p2p port), on every address; DNS on UDP 53 on
# the rig link's addresses (systemd-resolved holds 127.0.0.53), answering
# any A query for rig.test with SELF4. Python's standard library only (the
# VMs have no internet); runs as root, under systemd-run.
import os, socket, ssl, struct, subprocess, sys, threading

self4, self6 = sys.argv[1], sys.argv[2]
CERT, KEY = "/var/lib/rig/cert.pem", "/var/lib/rig/key.pem"
os.makedirs("/var/lib/rig", exist_ok=True)
if not os.path.exists(CERT):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", CERT,
                    "-days", "30", "-subj", "/CN=rig.test"], check=True, capture_output=True)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(CERT, KEY)


def recvn(c, n):
    b = b""
    while len(b) < n:
        part = c.recv(n - len(b))
        if not part:
            raise EOFError
        b += part
    return b


def https(c):
    t = tls.wrap_socket(c, server_side=True)
    t.recv(4096)
    body = b"repairer-rig https"
    t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
    t.close()


def smtp(c):
    c.sendall(b"220 rig.test ESMTP\r\n")
    c.recv(1024)
    c.sendall(b"221 rig.test bye\r\n")


def echo(c):
    n = struct.unpack(">I", recvn(c, 4))[0]
    c.sendall(struct.pack(">I", n) + recvn(c, n))


def tcp(port, handle):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", port))
    s.listen(16)

    def serve(c):
        try:
            c.settimeout(20)
            handle(c)
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def answer(q):
    # The question as asked, then one A record for it: the name by pointer.
    end = 12
    while q[end] != 0:
        end += q[end] + 1
    question = q[12:end + 5]
    head = q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    rr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(self4)
    return head + question + rr


def dns(family, addr):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, peer = s.recvfrom(512)
        try:
            s.sendto(answer(q), peer)
        except Exception:
            pass


tcp(443, https)
tcp(25, smtp)
tcp(26656, echo)
threading.Thread(target=dns, args=(socket.AF_INET, self4), daemon=True).start()
dns(socket.AF_INET6, self6)
