#!/usr/bin/env python3
"""The host side of the network tests: services the guest reaches at 10.0.2.2 (QEMU's user-mode network maps that
address to the host's loopback), and one connection the host makes into the guest through QEMU's port forward.

    7001/udp  echo
    7002/tcp  echo
    7003/tcp  source: sends 2 MiB of the test pattern (seed 7), then closes
    7004/tcp  sink: reads until the client finishes sending, answers crc32 and length (big endian u32 each), closes
    7006/tcp  a tiny HTTP server: every GET is answered with a page
    7005/tcp  slow echo: echoes in 100-byte pieces with a 5 ms pause between them
    inbound:  connects to 127.0.0.1:<forward port> until the guest answers "ping-from-host" with the same text in capitals

Usage: netpeer.py <forward port>. Runs until killed.
"""
import asyncio
import socket
import sys
import zlib

FWD = int(sys.argv[1]) if len(sys.argv) > 1 else 18077
SRC_LEN = 2 * 1024 * 1024
SRC_SEED = 7


def pattern(n, seed):
    # byte i of the guest's test pattern: ((i * 2654435761 + seed) mod 2^32) >> 16, low byte
    return bytes([(((i * 2654435761) + seed) & 0xFFFFFFFF) >> 16 & 0xFF for i in range(n)])


async def echo(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def slow_echo(reader, writer):
    try:
        while True:
            data = await reader.read(100)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            await asyncio.sleep(0.005)
    except ConnectionError:
        pass
    finally:
        writer.close()


async def http(reader, writer):
    try:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 4096:
            chunk = await reader.read(1024)
            if not chunk:
                break
            request += chunk
        path = request.split(b" ")[1].decode("ascii", "replace") if request.startswith(b"GET ") else "?"
        body = ("hello from the host, you asked for " + path + "\n").encode()
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
    except (ConnectionError, IndexError):
        pass
    finally:
        writer.close()


async def source(reader, writer, data=pattern(SRC_LEN, SRC_SEED)):
    try:
        writer.write(data)
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def sink(reader, writer):
    crc, n = 0, 0
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            crc = zlib.crc32(data, crc)
            n += len(data)
        writer.write(crc.to_bytes(4, "big") + n.to_bytes(4, "big"))
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


def inbound_once():
    """One attempt to talk to the guest's listener through the forwarded port; True when it answered as expected."""
    try:
        with socket.create_connection(("127.0.0.1", FWD), timeout=2) as s:
            s.sendall(b"ping-from-host\n")
            s.settimeout(3)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(100)
                if not chunk:
                    break
                buf += chunk
            return buf == b"PING-FROM-HOST\n"
    except OSError:
        return False


async def inbound():
    loop = asyncio.get_running_loop()
    while True:
        if await loop.run_in_executor(None, inbound_once):
            print("netpeer: the guest answered through the forwarded port", flush=True)
            return
        await asyncio.sleep(0.3)


async def main():
    servers = [
        await asyncio.start_server(echo, "127.0.0.1", 7002),
        await asyncio.start_server(source, "127.0.0.1", 7003),
        await asyncio.start_server(sink, "127.0.0.1", 7004),
        await asyncio.start_server(slow_echo, "127.0.0.1", 7005),
        await asyncio.start_server(http, "127.0.0.1", 7006),
    ]
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UdpEcho, local_addr=("127.0.0.1", 7001))
    print("netpeer: ready", flush=True)
    await inbound()
    await asyncio.sleep(10**6)


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
