import socket
import sys

try:
    s = socket.create_connection(("localhost", 2222), timeout=3)
    d = s.recv(64)
    sys.exit(0 if b"SSH" in d else 1)
except Exception:
    sys.exit(1)
