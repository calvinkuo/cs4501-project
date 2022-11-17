from __future__ import annotations

from proxy_server import *

ENTRY_PROXY_PORT = 51234
EXIT_PROXY_PORT = 51235


class EntryServer(Server):
    @staticmethod
    async def callback(client_reader: StreamReader, client_writer: StreamWriter):
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
        done, pending = await asyncio.wait([
                asyncio.create_task(pipe(port, client_reader, server_writer)),
                asyncio.create_task(pipe(port, server_reader, client_writer))
            ], return_when=asyncio.FIRST_COMPLETED)
        for future in pending:
            future.cancel()
        client_writer.close()
        server_writer.close()
        await client_writer.wait_closed()
        await server_writer.wait_closed()
        print(f'[{port}] Tunnel finished')


if __name__ == '__main__':
    asyncio.run(EntryServer(ENTRY_PROXY_PORT).start())
