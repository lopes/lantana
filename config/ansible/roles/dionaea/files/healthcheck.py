import os
import socket
import sys

SERVICES_DIR = "/opt/dionaea/etc/dionaea/services-enabled"


def probe_http():
    with socket.create_connection(("127.0.0.1", 80), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        resp = sock.recv(128)
        return b"HTTP/1." in resp


def probe_ftp():
    with socket.create_connection(("127.0.0.1", 21), timeout=3) as sock:
        sock.settimeout(3)
        resp = sock.recv(128)
        return b"220" in resp


def probe_mysql():
    with socket.create_connection(("127.0.0.1", 3306), timeout=3) as sock:
        sock.settimeout(3)
        resp = sock.recv(64)
        return len(resp) >= 4


def main():
    probes = [
        ("http.yaml", probe_http),
        ("ftp.yaml", probe_ftp),
        ("mysql.yaml", probe_mysql),
    ]
    ran = False
    for cfg_name, fn in probes:
        if os.path.exists(os.path.join(SERVICES_DIR, cfg_name)):
            ran = True
            try:
                if fn():
                    sys.exit(0)
            except Exception:
                sys.exit(1)
            sys.exit(1)

    if not ran:
        try:
            if probe_http():
                sys.exit(0)
        except Exception:
            sys.exit(1)
    sys.exit(1)


if __name__ == "__main__":
    main()
