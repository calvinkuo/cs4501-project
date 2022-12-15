from __future__ import annotations

import abc
import asyncio
import random
import socket
import traceback
from asyncio import StreamReader, StreamWriter
from collections.abc import Callable, Coroutine

NON_RESERVED_PORT_MIN = 49152
NON_RESERVED_PORT_MAX = 65535


# SOURCE: https://stackoverflow.com/a/166589
def get_local_ip_address() -> str:
    """Returns the proxy server's local IP address."""
    with socket.create_connection(('1.1.1.1', 80)) as s:
        return s.getsockname()[0]


async def pipe(port: int, reader: StreamReader,
               callback: Callable[[bytes], Coroutine] = lambda _: asyncio.sleep(0),
               eof_callback: Callable[[], Coroutine] = lambda: asyncio.sleep(0)):
    """Pipes data between from one stream to another."""
    try:
        while True:
            client_data = await asyncio.wait_for(reader.read(4096), timeout=120)
            if not client_data:
                print(f'[{port}] Pipe reached EOF')
                await eof_callback()
                break
            # print(f'[{port}] Sent through pipe: {client_data!r}')
            print(f'[{port}] Sent {len(client_data)} bytes through pipe')
            await callback(client_data)
    except asyncio.TimeoutError:
        print(f'[{port}] Pipe timed out')
    except ConnectionResetError:
        print(f'[{port}] Pipe connection reset')
    except (EOFError, OSError):
        print(f'[{port}] Pipe error')
        print(traceback.format_exc())


class Server(abc.ABC):
    """A TCP server. Incoming connections are handled through the ``client_connected`` method."""

    def __init__(self, port: int = None):
        self.port = port if port is not None else random.randint(NON_RESERVED_PORT_MIN, NON_RESERVED_PORT_MAX)
        self.server = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.server.is_serving():
            await self.stop()

    async def start(self):
        """Starts the server."""
        self.server = await asyncio.start_server(self.client_connected, '0.0.0.0', self.port, start_serving=True)
        print(f'Server running on {get_local_ip_address()}:{self.port}')
        try:
            await self.server.serve_forever()
        except asyncio.exceptions.CancelledError:
            print(f'Server task was canceled')

    async def stop(self):
        """Stops the server."""
        print(f'Stopping server')
        self.server.close()
        await self.server.wait_closed()
        print(f'Closed server')

    @abc.abstractmethod
    async def client_connected(self, client_reader: StreamReader, client_writer: StreamWriter):
        raise NotImplementedError
