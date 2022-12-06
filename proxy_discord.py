from __future__ import annotations

import abc
import asyncio
import binascii
import io
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

        packets_to_send: deque[Packable] = deque()
        while True:
            # print("Packet loop")
            while not self.pending_packets.empty():
                p = self.pending_packets.get_nowait()
                packets_to_send.append(p)
                # print("Retrieved packet from queue")
            if self.channel and packets_to_send:
                # print(f'Sending bundle')
                payload = PacketBundleEncrypted(list(packets_to_send))
                packets_to_send.clear()
                while len(payload) > self.MAX_MSG_LEN:
                    packets_to_send.appendleft(payload.packets[-1])
                    payload = PacketBundleEncrypted(payload.packets[:-1])
                # TODO: combine packets with same destination/port to prevent out-of-order delivery
                # split packets if exceeds payload size
                # change read_from to return immediately, since the bundling is handled here
                content = payload.pack()
                await self.channel.send("", file=discord.File(io.BytesIO(content),
                                                              f'{SHA256.new(content).hexdigest()[:8]}.bin'))
                print(f'Sent bundle of {len(payload.packets)} packets')
            await asyncio.sleep(0)
            # print("Packet loop ended")

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
