"""Wake-on-LAN — send a magic packet to a MAC address."""

import socket


def wake(mac: str):
    clean = mac.replace(":", "").replace("-", "")
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC: {mac}")
    payload = b"\xff" * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(payload, ("<broadcast>", 9))
