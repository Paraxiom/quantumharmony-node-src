#!/usr/bin/env python3
"""A plain TCP forwarder, so a validator can be partitioned without touching
the firewall and without asking macOS for administration rights.

Deliberately not the PQTG relay: the gadget is transport agnostic and the
partition test should not depend on, or be confounded by, the relay.

  tcp_forward.py <listen_port> <target_host> <target_port>

Kill it to cut the link. Start it again to heal.
"""
import asyncio, sys


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(local_r, local_w, host, port):
    try:
        remote_r, remote_w = await asyncio.open_connection(host, port)
    except Exception:
        local_w.close()
        return
    await asyncio.gather(pipe(local_r, remote_w), pipe(remote_r, local_w))


async def main():
    listen, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, host, port), "127.0.0.1", listen)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
