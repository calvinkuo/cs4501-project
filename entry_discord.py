from __future__ import annotations

import asyncio
import os
import traceback
from asyncio import StreamReader, StreamWriter

import pac
from packet import PacketFlag, Packet
from proxy_discord import DiscordBot
from proxy_server import Server, HTTPRequest, HTTPError, ReaderWriterPair, get_local_ip_address, pipe


class EntryServer(Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reader_writer_dict: dict[int, ReaderWriterPair] = {}
        self.port_dst_id: dict[int, int] = {}

    async def start(self):
        pac.make_pac(get_local_ip_address(), self.port)
        await asyncio.gather(pac.start(), super().start())

    async def callback(self, client_reader: StreamReader, client_writer: StreamWriter):
        # Get the client's port
        port: int = client_writer.get_extra_info('peername')[1]
        print(f'[{port}] Entry node connected')
        if port in self.port_dst_id:
            del self.port_dst_id[port]

        # Wait until a complete HTTP request is sent
        try:
            req: HTTPRequest = await asyncio.wait_for(HTTPRequest.from_reader(client_reader, limit=my_bot.MAX_MSG_LEN), timeout=120)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
            await my_bot.send_packet(0, port, flags=PacketFlag.BGN, payload=bytes(req))
        except asyncio.TimeoutError:
            print(f'[{port}] Entry node timed out')
            res = b'HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n'
            client_writer.write(res)
            print(f'[{port}] Sent to entry node: {res!r}')
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return
        except HTTPError as e:
            print(f'[{port}] Entry node request too long')
            client_writer.write(e.res)
            print(f'[{port}] Sent to entry node: {e.res!r}')
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return
        except ConnectionResetError:
            print(f'[{port}] Entry node connection reset')
            # Connection is already closed, so no need to send an error message
            return
        except (EOFError, OSError):
            print(f'[{port}] Entry node error')
            print(traceback.format_exc())
            # Did not finish establishing HTTP connection, so just end the connection
            client_writer.close()
            await client_writer.wait_closed()
            return
        req.headers.proxy()

        # Save reader and writer
        self.reader_writer_dict[port] = ReaderWriterPair(client_reader, client_writer)
        # if req.method == 'CONNECT':
        #     res = b'HTTP/1.1 200 OK\r\n\r\n'
        #     print(f'[{port}] Sent through pipe: {res!r}')
        #     client_writer.write(res)
        #     await client_writer.drain()

        # Wait for exit node to respond
        async def wait_for_dst(port_num):
            while port_num not in self.port_dst_id:
                await asyncio.sleep(0.1)
            return self.port_dst_id[port_num]

        try:
            dst = await asyncio.wait_for(wait_for_dst(port), timeout=120)
        except asyncio.TimeoutError:
            print(f'[{port}] Exit node timed out')
            res = b'HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n'
            client_writer.write(res)
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Pipe data from reader to Discord
        async def callback(data: bytes):
            await asyncio.wait_for(my_bot.send_packet(dst, port, payload=data), timeout=120)

        async def eof_callback():
            # await my_bot.send_packet(dst, port, flags=PacketFlag.END)
            pass

        await pipe(port, client_reader, callback, eof_callback)

        # Leave connection open for server to respond

    async def receive(self, packet: Packet):
        if packet.port in self.reader_writer_dict:
            reader, writer = self.reader_writer_dict[packet.port]
            reader: StreamReader
            writer: StreamWriter
            if not writer.is_closing():
                if packet.payload:
                    writer.write(packet.payload)
                    print(f'[{packet.port}] Sent to client: {len(packet.payload)} bytes')
                await writer.drain()
                if PacketFlag.BGN in packet.flags:
                    self.port_dst_id[packet.port] = packet.src
                if PacketFlag.END in packet.flags:
                    writer.close()
                    await writer.wait_closed()
                    print(f'[{packet.port}] Closed writer')


class EntryDiscordBot(DiscordBot):
    async def callback(self, packet: Packet):
        if not self.is_ready():
            await self.wait_until_ready()
        # print('Received', packet)
        await my_server.receive(packet)


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    try:
        my_server = EntryServer(60123)
        my_bot = EntryDiscordBot()
        asyncio.ensure_future(my_server.start(), loop=loop)
        asyncio.ensure_future(my_bot.start(os.environ['TOKEN']), loop=loop)
        loop.run_forever()
    finally:
        loop.close()
