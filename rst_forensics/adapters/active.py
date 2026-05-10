"""Active probe — initiate a real TCP connection and watch for the RST.

The OS handles the handshake (so we capture a genuine SYN-ACK and lock the
server baseline). We send a small request, drain the socket until either the
peer closes or ``timeout`` elapses, then stop the sniffer. Anything that
arrived with ``RST`` set ends up in the returned list.
"""

from __future__ import annotations

import socket
import time

from ..flow import FlowTracker
from ..observation import RstObservation
from . import _scapy

_PROBE_PAYLOAD = b"GET / HTTP/1.0\r\nHost: rst-forensics\r\n\r\n"


def probe(
    host: str,
    port: int,
    timeout: float = 5.0,
    iface: str | None = None,
    payload: bytes = _PROBE_PAYLOAD,
) -> list[RstObservation]:
    """Connect to ``(host, port)``; return every RST observed end-to-end."""
    from scapy.all import AsyncSniffer  # noqa: import-time scapy guard

    addr = socket.gethostbyname(host)
    bpf = f"tcp and host {addr} and port {port}"

    tracker = FlowTracker()
    out: list[RstObservation] = []

    def _handle(pkt) -> None:
        meta = _scapy.to_meta(pkt)
        if meta is None:
            return
        obs = tracker.update(meta)
        if obs is not None:
            out.append(obs)

    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handle, store=False)
    sniffer.start()
    try:
        # Tiny grace so the BPF is in place before SYN goes out.
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            try:
                sock.connect((addr, port))
                if payload:
                    try:
                        sock.sendall(payload)
                    except OSError:
                        pass
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    except OSError:
                        break
                    if not chunk:
                        break
            except (OSError, socket.timeout):
                # Connection refused / RST'd / timed out — sniffer caught it.
                pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
        # Let the closing packets settle into the sniffer queue.
        time.sleep(0.2)
    finally:
        if sniffer.running:
            sniffer.stop()

    return out
