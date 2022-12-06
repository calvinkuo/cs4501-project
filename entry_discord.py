from __future__ import annotations

import asyncio
import os
import traceback
from asyncio import StreamReader, StreamWriter

import pac
from proxy_discord import DiscordBot, Packet, PacketFlag
from proxy_server import Server, HTTPRequest, ReaderWriterPair, get_local_ip_address, read_from


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
            req = await asyncio.wait_for(HTTPRequest.from_reader(client_reader), timeout=60)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
            await my_bot.send_packet(0, port, flags=PacketFlag.BGN, payload=bytes(req))
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

        # Save reader and writer
        self.reader_writer_dict[port] = ReaderWriterPair(client_reader, client_writer)
        # if req.method == 'CONNECT':
        #     res = b'HTTP/1.1 200 OK\r\n\r\n'
        #     print(f'[{port}] Sent through pipe: {res!r}')

        # Wait for exit node to respond
        while port not in self.port_dst_id:
            await asyncio.sleep(0.1)
        dst = self.port_dst_id[port]

        # Pipe data from reader to Discord
        try:
            while True:
                client_data = await asyncio.wait_for(read_from(client_reader, DiscordBot.READ_SIZE), timeout=600)
                if not client_data:
                    print(f'[{port}] Pipe reached EOF')
                    # await my_bot.send_packet(dst, port, flags=PacketFlag.END, payload=b'')
                    break
                # print(f'[{port}] Sent through pipe: {client_data!r}')
                print(f'[{port}] Sent {len(client_data)} bytes through pipe')
                await asyncio.wait_for(my_bot.send_packet(dst, port, payload=client_data), timeout=30)
                # print(f'[{port}] Sent to Discord: {bytes(req)!r}')
        except asyncio.TimeoutError:
            print(f'[{port}] Pipe timed out')
        except ConnectionResetError:
            print(f'[{port}] Pipe connection reset')
        except (EOFError, OSError):
            print(f'[{port}] Pipe error')
            print(traceback.format_exc())

        # Close connection
        # if not client_writer.is_closing():
        #     await client_writer.drain()
        #     client_writer.close()
        #     await client_writer.wait_closed()
        #     print(f'[{port}] Closed writer')

    async def receive(self, packet: Packet):
        if packet.port in self.reader_writer_dict:
            reader, writer = self.reader_writer_dict[packet.port]
            reader: StreamReader
            writer: StreamWriter
            if not writer.is_closing():
                writer.write(packet.payload)
                print(f'[{packet.port}] Sent to client: {len(packet.payload)} bytes')
                await writer.drain()
                if PacketFlag.BGN in packet.flags:
                    self.port_dst_id[packet.port] = packet.src
                if PacketFlag.END in packet.flags:
                    writer.close()
                    await writer.wait_closed()
                    # print(f'[{port}] Closed writer')


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
