from __future__ import annotations

import asyncio
import traceback
from asyncio import StreamReader, StreamWriter

from tcp_server import Server, pipe

ENTRY_PROXY_PORT = 60123
EXIT_PROXY_PORT = 51235


class EntryServer(Server):
    async def client_connected(self, client_reader: StreamReader, client_writer: StreamWriter):
        """Creates a tunnel between the client and the request server.
        This method runs until either the client or the request server closes the connection."""
        # Get the client's port
        port = client_writer.get_extra_info('peername')[1]
        print(f'[{port}] Client connected')

        # Open a connection to the exit node
        try:
            server_reader, server_writer = await asyncio.open_connection('localhost', EXIT_PROXY_PORT)
        except asyncio.TimeoutError:
            print(f'[{port}] Exit node timed out')
            return
        except (EOFError, OSError):
            print(f'[{port}] Exit node error')
            print(traceback.format_exc())
            return

        # Continue piping messages back-and-forth until one of the connections is closed
        async def server_callback(data: bytes):
            server_writer.write(data)
            await server_writer.drain()

        async def client_callback(data: bytes):
            client_writer.write(data)
            await client_writer.drain()

        done, pending = await asyncio.wait([
                asyncio.create_task(pipe(port, client_reader, server_callback)),
                asyncio.create_task(pipe(port, server_reader, client_callback))
            ], return_when=asyncio.ALL_COMPLETED)
        for future in pending:
            future.cancel()
        client_writer.close()
        server_writer.close()
        await client_writer.wait_closed()
        await server_writer.wait_closed()
        print(f'[{port}] Tunnel finished')


if __name__ == '__main__':
    asyncio.run(EntryServer(ENTRY_PROXY_PORT).start())
