from __future__ import annotations

import asyncio
import os
import traceback
from asyncio import StreamReader, StreamWriter

from packet import PacketFlag, Packet
from proxy_discord import DiscordBot
from proxy_server import Server, HTTPRequest, ReaderWriterPair, pipe


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
            if not server_writer.is_closing():
                if packet.payload:
                    server_writer.write(packet.payload)
                    print(f'[{port}] Sent to server: {len(packet.payload)} bytes')
                await server_writer.drain()
                if PacketFlag.END in packet.flags:
                    server_writer.close()
                    await server_writer.wait_closed()
                    print(f'[{port}] Closed writer')
        elif PacketFlag.BGN in packet.flags and (packet.src, port) not in self.reader_writer_dict:
            print(f'[{port}] Entry node connected')

            # Complete headers for a HTTP request should have been sent
            req = HTTPRequest.from_bytes(packet.payload)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
            req.headers.proxy()

            # Open a connection to the server specified in the request
            try:
                server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(*req.target), timeout=120)
                print(f'[{port}] Connected to server')
            except asyncio.TimeoutError:
                print(f'[{port}] Server timed out')
                # The entry node will time out and serve a 504 Gateway Timeout to the client
                return
            except (EOFError, OSError):
                print(f'[{port}] Server error')
                print(traceback.format_exc())
                res = b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'
                await my_bot.send_packet(packet.src, port, flags=PacketFlag.BGN | PacketFlag.END, payload=res)
                return

            # Save reader and writer
            self.reader_writer_dict[(packet.src, port)] = ReaderWriterPair(server_reader, server_writer)

            # If using HTTPS tunneling, respond to client with 200 OK so that it can begin TLS negotiation
            if req.method == 'CONNECT':
                res = b'HTTP/1.1 200 OK\r\n\r\n'
                # res = b''
                # pass
            # Otherwise, send the initial request to the server directly
            else:
                res = b''
                server_writer.write(packet.payload)
                print(f'[{port}] Sent to server: {bytes(packet.payload)!r}')
            await my_bot.send_packet(packet.src, port, flags=PacketFlag.BGN, payload=res)
            # await my_bot.send_packet(packet.src, port, flags=PacketFlag.BGN)
            print(f'[{port}] Sent to entry node: {res!r}')

            # Pipe data from server to Discord
            async def callback(data: bytes):
                await asyncio.wait_for(my_bot.send_packet(packet.src, port, payload=data), timeout=120)

            async def eof_callback():
                # await my_bot.send_packet(packet.src, port, flags=PacketFlag.END)
                pass

            await pipe(port, server_reader, callback, eof_callback)

            # Leave connection open for client to respond


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
