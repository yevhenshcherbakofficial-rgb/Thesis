#!/usr/bin/env python3
"""
sink.py - Network sink for the isolated lab (runs on the lab-sink VM, 10.0.0.2).

Gives guest traffic somewhere to go without anything leaving the internal
network `labnet`:

  * DNS (UDP 53): every A query is answered with SINK_IP, so domain lookups by
    workloads and malware samples resolve to the sink instead of failing.
  * TCP (any port): nftables redirects every inbound TCP port (except 22) to
    LISTEN_PORT. The listener accepts the connection, reads what the client
    sends, answers HTTP requests with a minimal 200 response and logs the
    original destination port via SO_ORIGINAL_DST.

Every DNS query and TCP session is written as a JSON line to LOG_PATH, which is
useful as ground truth for network behaviour of samples.

Standard library only (Python 3.9+). Run as root (binds port 53).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import socket
import struct

SINK_IP = "10.0.0.2"
LISTEN_PORT = 8000
LOG_PATH = "/var/log/sink/sink.jsonl"
SO_ORIGINAL_DST = 80
HTTP_BODY = b"<html><body>ok</body></html>"


def log(rec: dict) -> None:
    rec["ts"] = dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- DNS ----------
def _qname(data: bytes, off: int) -> tuple[str, int]:
    labels = []
    while off < len(data):
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:                       # compression pointer (not expected in queries)
            off += 2
            break
        labels.append(data[off + 1: off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), off


def dns_answer(query: bytes) -> tuple[bytes, str, int]:
    tid, flags, qd = struct.unpack(">HHH", query[:6])
    name, off = _qname(query, 12)
    qtype, qclass = struct.unpack(">HH", query[off: off + 4])
    question = query[12: off + 4]
    rflags = 0x8180 | (flags & 0x0100)     # response, RD copied, RA, no error
    if qtype == 1:                         # A
        hdr = struct.pack(">HHHHHH", tid, rflags, 1, 1, 0, 0)
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(SINK_IP)
        return hdr + question + ans, name, qtype
    hdr = struct.pack(">HHHHHH", tid, rflags, 1, 0, 0, 0)  # other types: empty answer
    return hdr + question, name, qtype


class DNSProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            resp, name, qtype = dns_answer(data)
            self.transport.sendto(resp, addr)
            log({"proto": "dns", "src": addr[0], "qname": name, "qtype": qtype})
        except Exception as exc:          # malformed packet
            log({"proto": "dns", "src": addr[0], "error": str(exc)})


# ---------------------------------------------------------------- TCP ----------
def original_port(writer: asyncio.StreamWriter) -> int | None:
    sock = writer.get_extra_info("socket")
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        return struct.unpack(">H", raw[2:4])[0]
    except OSError:
        return None


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    dport = original_port(writer)
    first = b""
    try:
        first = await asyncio.wait_for(reader.read(2048), timeout=5)
        if first[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or first[:7] == b"OPTIONS":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                         + str(len(HTTP_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + HTTP_BODY)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        log({"proto": "tcp", "src": peer[0], "sport": peer[1], "dport": dport,
             "bytes": len(first), "head": first[:64].hex()})
        writer.close()


async def main() -> None:
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(DNSProtocol, local_addr=("0.0.0.0", 53))
    server = await asyncio.start_server(handle_tcp, "0.0.0.0", LISTEN_PORT, backlog=1024)
    log({"proto": "sink", "event": "started"})
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
