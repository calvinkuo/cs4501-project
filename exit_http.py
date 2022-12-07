from __future__ import annotations

from proxy_server import *

ENTRY_PROXY_PORT = 51234
EXIT_PROXY_PORT = 51235


class ExitServer(Server):
    async def callback(self, client_reader: StreamReader, client_writer: StreamWriter):
        """Creates a tunnel between the client and the server it requests to connect to.
        This method runs until either the client or the server closes the connection."""
        # Get the client's port
        port = client_writer.get_extra_info('peername')[1]
        print(f'[{port}] Entry node connected')

        # Wait until a complete HTTP request is sent
        try:
            req = await asyncio.wait_for(HTTPRequest.from_reader(client_reader), timeout=30)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
        except asyncio.TimeoutError:
            print(f'[{port}] Entry node timed out')
            return
        except ConnectionResetError:
            print(f'[{port}] Entry node connection reset')
            return
        except (EOFError, OSError):
            print(f'[{port}] Entry node error')
            print(traceback.format_exc())
            return
        req.headers.proxy()

        # Open a connection to the server specified in the request
        try:
            server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(*req.target), timeout=30)
            print(f'[{port}] Connected to server')
        except asyncio.TimeoutError:
            print(f'[{port}] Server timed out')
            return
        except (EOFError, OSError):
            print(f'[{port}] Server error')
            print(traceback.format_exc())
            return

        # If using HTTPS tunneling, respond to client with 200 OK so that it can begin TLS negotiation
        if req.method == 'CONNECT':
            res = b'HTTP/1.1 200 OK\r\n\r\n'
            client_writer.write(res)
            print(f'[{port}] Sent to entry node: {res!r}')
        # Otherwise, send the initial request to the server directly
        else:
            server_writer.write(bytes(req))
            print(f'[{port}] Sent to server: {bytes(req)!r}')

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
    asyncio.run(ExitServer(EXIT_PROXY_PORT).start())
