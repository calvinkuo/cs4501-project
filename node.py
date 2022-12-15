import abc
import asyncio
import functools
import random
import traceback
from asyncio import StreamReader, StreamWriter
from typing import NamedTuple

from http_request import HTTPRequest, HTTPError
from packet import Packet, PacketFlag
from tcp_server import Server, pipe


class ReaderWriterPair(NamedTuple):
    reader: StreamReader
    writer: StreamWriter


class Node:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = random.randrange(1, 2 ** 32)

    @abc.abstractmethod
    async def packet_queue(self, packet: Packet):
        raise NotImplementedError

    async def packet_send(self, dst: int, port: int, data: bytes = b'', *, flags: PacketFlag = PacketFlag(0)):
        """Sends a packet."""
        packet = Packet(self.id, dst, port, flags=flags, payload=data)
        await self.packet_queue(packet)

    @abc.abstractmethod
    async def packet_receive(self, packet: Packet):
        """Receives a packet."""
        raise NotImplementedError


class EntryNode(Node, Server, abc.ABC):
    MAX_MSG_LEN = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reader_writer_dict: dict[int, ReaderWriterPair] = {}
        self.port_dst_id: dict[int, int] = {}

    async def packet_receive(self, packet: Packet):
        if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
            # Get the client's port
            port: int = packet.port

            # Existing connection
            if port in self.reader_writer_dict:
                reader, writer = self.reader_writer_dict[port]
                reader: StreamReader
                writer: StreamWriter
                if not writer.is_closing():
                    if packet.payload:
                        writer.write(packet.payload)
                        print(f'[{port}] Sent to client: {len(packet.payload)} bytes')
                    await writer.drain()
                    if PacketFlag.BGN in packet.flags:
                        self.port_dst_id[port] = packet.src
                        # print("Added dst", port, packet.src)
                    if PacketFlag.END in packet.flags:
                        writer.close()
                        await writer.wait_closed()
                        print(f'[{port}] Closed writer')

    async def wait_for_exit_node(self, port_num):
        while port_num not in self.port_dst_id:
            # print("Waiting for dst", port_num)
            await asyncio.sleep(0.1)
        # print("Got dst", port_num, self.port_dst_id[port_num])
        return self.port_dst_id[port_num]

    async def client_connected(self, client_reader: StreamReader, client_writer: StreamWriter):
        # Get the client's port
        port: int = client_writer.get_extra_info('peername')[1]
        print(f'[{port}] Entry node connected')
        if port in self.port_dst_id:
            del self.port_dst_id[port]

        # Wait until a complete HTTP request is sent
        try:
            req: HTTPRequest = await asyncio.wait_for(HTTPRequest.from_reader(client_reader, limit=self.MAX_MSG_LEN), timeout=120)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
            await self.packet_send(0, port, bytes(req), flags=PacketFlag.BGN)
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

        # Wait for exit node to respond
        try:
            dst = await asyncio.wait_for(self.wait_for_exit_node(port), timeout=120)
        except asyncio.TimeoutError:
            print(f'[{port}] Exit node timed out')
            res = b'HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n'
            client_writer.write(res)
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Pipe data from reader to Discord
        await pipe(port, client_reader,
                   functools.partial(self.packet_send, dst, port),
                   functools.partial(self.packet_send, dst, port, flags=PacketFlag.END))

        # Leave connection open for server to respond


class ExitNode(Node, abc.ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reader_writer_dict: dict[tuple[int, int], ReaderWriterPair] = {}

    async def packet_receive(self, packet: Packet):
        if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
            # Get the client's port
            port: int = packet.port

            # Existing connection
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

            # New connection
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
                    await self.packet_send(packet.src, port, res, flags=PacketFlag.BGN | PacketFlag.END)
                    return

                # Save reader and writer
                self.reader_writer_dict[(packet.src, port)] = ReaderWriterPair(server_reader, server_writer)

                # If using HTTPS tunneling, respond to client with 200 OK so that it can begin TLS negotiation
                if req.method == 'CONNECT':
                    res = b'HTTP/1.1 200 OK\r\n\r\n'
                # Otherwise, send the initial request to the server directly
                else:
                    res = b''
                    server_writer.write(packet.payload)
                    print(f'[{port}] Sent to server: {bytes(packet.payload)!r}')
                await self.packet_send(packet.src, port, res, flags=PacketFlag.BGN)
                print(f'[{port}] Sent to entry node: {res!r}')

                # Pipe data from server to Discord
                await pipe(port, server_reader,
                           functools.partial(self.packet_send, packet.src, port),
                           functools.partial(self.packet_send, packet.src, port, flags=PacketFlag.END))

                # Leave connection open for client to respond
