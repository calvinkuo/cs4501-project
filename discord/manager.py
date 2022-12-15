from __future__ import annotations

import abc
import asyncio
import binascii
import functools
import io
import operator
import os
import random
import struct
from asyncio import Queue
from collections import deque

import discord
import dotenv
from Cryptodome.Hash import SHA256

from packet import Packable, PacketFlag, Packet, PacketEncrypted, PacketBundleEncrypted

dotenv.load_dotenv()


class DiscordBot(discord.Client, abc.ABC):
    MAX_MSG_LEN = 8 * 2 ** 20
    READ_SIZE = MAX_MSG_LEN - PacketEncrypted.HEADER_LEN

    def __init__(self, **options):
        super().__init__(intents=discord.Intents(messages=True, guilds=True), **options)
        self.id = random.randrange(1, 2 ** 32)
        self.channel: discord.TextChannel | None = None
        self.pending_packets: Queue[Packet] = Queue()

    async def on_ready(self):
        print(f'Logged in!')
        self.channel = self.get_channel(int(os.environ['CHANNEL_ID']))

        packets_to_send: deque[Packet] = deque()
        while True:
            # If there are no pending packets or packets to send, wait until a packet is available
            if self.pending_packets.empty() and not packets_to_send:
                p = await self.pending_packets.get()
                packets_to_send.append(p)

            # Retrieve any packets currently on the queue
            while not self.pending_packets.empty():
                p = self.pending_packets.get_nowait()
                packets_to_send.append(p)

            # If there are packets to send
            if self.channel and packets_to_send:
                # Create bundle from packets
                payload = PacketBundleEncrypted(list(packets_to_send))
                packets_to_send.clear()

                # Defer later packets if the bundle is too large
                while len(payload) > self.MAX_MSG_LEN:
                    packets_to_send.appendleft(payload.packets[-1])
                    payload = PacketBundleEncrypted(payload.packets[:-1])

                # If we can fit part of the last packet, then split it and send part of it now
                if packets_to_send:
                    space_remaining = self.MAX_MSG_LEN - len(payload)
                    split_location = space_remaining - Packet.HEADER_LEN - PacketBundleEncrypted.HEADER_INDEX_LEN
                    if split_location > 0:
                        print(f'Splitting packet')
                        packet_old = packets_to_send.popleft()
                        packet_a = Packet(packet_old.src, packet_old.dst, packet_old.port, packet_old.flags,
                                          packet_old.payload[:split_location])
                        packet_b = Packet(packet_old.src, packet_old.dst, packet_old.port, packet_old.flags,
                                          packet_old[split_location:])
                        packets_to_send.appendleft(packet_b)
                        payload = PacketBundleEncrypted(payload.packets + [packet_a])
                assert len(payload) <= self.MAX_MSG_LEN

                # Since the received packets may be processed out-of-order, combine packets with same destination/port
                dst_dict: dict[tuple[int, int, int], list[int]] = {}
                for i, p in enumerate(payload.packets):
                    key = p.src, p.dst, p.port
                    if key not in dst_dict:
                        dst_dict[key] = [i]
                    else:
                        dst_dict[key].append(i)

                packets_to_remove: list[int] = []
                packets_to_add: list[Packet] = []
                for k, v in dst_dict.items():
                    if len(v) > 1:
                        packets_to_remove += v
                        old_p = [payload.packets[i] for i in v]
                        p = Packet(k[0], k[1], k[2],
                                   functools.reduce(operator.or_, (p.flags for p in old_p)),
                                   b''.join(p.payload for p in old_p))
                        packets_to_add.append(p)

                if packets_to_remove or packets_to_add:
                    print(f'Merging packets: removing {len(packets_to_remove)}, adding {len(packets_to_add)}')
                    payload = PacketBundleEncrypted([p for i, p in enumerate(payload.packets)
                                                     if i not in packets_to_remove] + packets_to_add)

                # Send the bundle to the channel
                content = payload.pack()
                await self.channel.send("", file=discord.File(io.BytesIO(content),
                                                              f'{SHA256.new(content).hexdigest()[:8]}.bin'))
                print(f'Sent bundle of {len(payload.packets)} packets')

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            try:
                # packet = PacketEncrypted.unpack(base65536.decode(message.content))
                # packet = PacketEncrypted.unpack(await message.attachments[0].read())
                # await self.callback(packet)
                bundle = PacketBundleEncrypted.unpack(await message.attachments[0].read())
                packets = []
                for packet in bundle.packets:
                    if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
                        packets.append(packet)
                if packets:
                    print(f'Received bundle of {len(packets)} packets')
                    await asyncio.gather(*(self.callback(packet) for packet in packets))
                    await message.delete(delay=60)
            except (struct.error, binascii.Error):
                print('Invalid packet!')
            except (ValueError, KeyError):
                print('Could not decrypt packet!')

    async def send_packet(self, dst: int, port: int, *, flags: PacketFlag = PacketFlag(0), payload: bytes = b''):
        # if self.channel:
        #     packet = PacketEncrypted(self.id, dst, port, flags, payload)
        #     content = base65536.encode(packet.pack())
        #     if len(content) > 2000:
        #         print("Error: content is too long", len(content))
        #     await self.channel.send(content)
        #     content = packet.pack()

        packet = Packet(self.id, dst, port, flags, payload)
        await self.pending_packets.put(packet)
        print("Put packet in queue")

    @abc.abstractmethod
    async def callback(self, packet: Packet):
        raise NotImplementedError
