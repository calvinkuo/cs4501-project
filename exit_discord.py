from __future__ import annotations

import asyncio
import os
import traceback
from asyncio import StreamReader, StreamWriter

from proxy_discord import DiscordBot, Packet, PacketFlag
from proxy_server import Server, HTTPRequest, ReaderWriterPair, read_from


class ExitServer(Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reader_writer_dict: dict[tuple[int, int], ReaderWriterPair] = {}

    async def callback(self, client_reader: StreamReader, client_writer: StreamWriter):
        raise NotImplementedError

    async def receive(self, packet: Packet):
        # Get the client's port
        port: int = packet.port

        if (packet.src, port) in self.reader_writer_dict:
            server_writer = self.reader_writer_dict[packet.src, port].writer
            server_writer.write(bytes(packet.payload))
            print(f'[{port}] Sent to server: {len(packet.payload)} bytes')
            await server_writer.drain()
            if PacketFlag.END in packet.flags:
                server_writer.close()
                await server_writer.wait_closed()
                # print(f'[{port}] Closed writer')
        elif PacketFlag.BGN in packet.flags and (packet.src, port) not in self.reader_writer_dict:
            print(f'[{port}] Entry node connected')

            # TODO: cache until this occurs
            # A complete HTTP request should have been sent
            try:
                req = HTTPRequest.from_bytes(packet.payload)
                print(f'[{port}] Got initial request') #  : {bytes(req)!r}')
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
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(*req.target), timeout=60)
                print(f'[{port}] Connected to server')
            except asyncio.TimeoutError:
                print(f'[{port}] Server timed out')
                return
            except (EOFError, OSError):
                print(f'[{port}] Server error')
                print(traceback.format_exc())
                return

            # Save reader and writer
            self.reader_writer_dict[(packet.src, port)] = ReaderWriterPair(server_reader, server_writer)

            # If using HTTPS tunneling, respond to client with 200 OK so that it can begin TLS negotiation
            if req.method == 'CONNECT':
                res = b'HTTP/1.1 200 OK\r\n\r\n'
                # pass
            # Otherwise, send the initial request to the server directly
            else:
                res = b''
                server_writer.write(bytes(req))
                print(f'[{port}] Sent to server: {bytes(req)!r}')
            await my_bot.send_packet(packet.src, port, flags=PacketFlag.BGN, payload=res)
            # await my_bot.send_packet(packet.src, port, flags=PacketFlag.BGN)
            print(f'[{port}] Sent to entry node: {res!r}')

            # Pipe data from server to Discord
            try:
                while True:
                    server_data = await asyncio.wait_for(read_from(server_reader, DiscordBot.READ_SIZE), timeout=600)
                    if not server_data:
                        print(f'[{port}] Pipe reached EOF')
                        # await my_bot.send_packet(packet.src, port, flags=PacketFlag.END)
                        break
                    # print(f'[{port}] Sent through pipe: {client_data!r}')
                    print(f'[{port}] Sent {len(server_data)} bytes through pipe')
                    await asyncio.wait_for(my_bot.send_packet(packet.src, port, payload=server_data), timeout=30)
                    # print(f'[{port}] Sent to Discord: {server_data!r}')
            except asyncio.TimeoutError:
                print(f'[{port}] Pipe timed out')
            except ConnectionResetError:
                print(f'[{port}] Pipe connection reset')
            except (EOFError, OSError):
                print(f'[{port}] Pipe error')
                print(traceback.format_exc())

            # Close connection
            # if not server_writer.is_closing():
            #     await server_writer.drain()
            #     server_writer.close()
            #     await server_writer.wait_closed()
            #     print(f'[{port}] Closed writer')


class ExitDiscordBot(DiscordBot):
    async def callback(self, packet: Packet):
        if not self.is_ready():
            await self.wait_until_ready()
        # print('Received', packet)
        await my_server.receive(packet)


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    try:
        my_server = ExitServer()
        my_bot = ExitDiscordBot()
        # asyncio.ensure_future(my_server.start(), loop=loop)
        asyncio.ensure_future(my_bot.start(os.environ['TOKEN']), loop=loop)
        loop.run_forever()
    finally:
        loop.close()
