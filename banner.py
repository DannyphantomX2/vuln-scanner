#!/usr/bin/env python3

import socket
from typing import Optional

TIMEOUT = 3.0
BUFFER_SIZE = 1024

HTTP_REQUEST = b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
GENERIC_PROBE = b"\r\n"


def grab_banner(host: str, port: int) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((host, port))

        if port in (80, 8080, 8000, 443):
            sock.sendall(HTTP_REQUEST.replace(b"{host}", host.encode()))
        else:
            sock.sendall(GENERIC_PROBE)

        banner = sock.recv(BUFFER_SIZE)
        return banner.decode(errors="ignore").strip() or None

    except (socket.timeout, socket.error, OSError):
        return None

    finally:
        sock.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    result = grab_banner(host, port)

    if result:
        print(f"Banner from {host}:{port}\n{result}")
    else:
        print(f"No banner received from {host}:{port}")
