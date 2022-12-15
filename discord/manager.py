from __future__ import annotations

import binascii
import io
import os
import struct
from abc import ABC

import discord
from Cryptodome.Hash import SHA256

from packet import PacketBundleEncrypted, PacketManager, Packable


class DiscordPacketManager(PacketManager, discord.Client, ABC):
    MAX_MSG_LEN = 8 * 2 ** 20  # 8 MB

    def __init__(self, **options):
        super().__init__(intents=discord.Intents(messages=True, guilds=True), **options)
        self.channel: discord.TextChannel | None = None

    async def on_ready(self):
        print(f'Logged in!')
        self.channel = self.get_channel(int(os.environ['CHANNEL_ID']))
        await self.packet_loop()

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            try:
                bundle = PacketBundleEncrypted.unpack(await message.attachments[0].read())
                await self.packet_bundle_receive(bundle)
                await message.delete(delay=60)
            except (struct.error, binascii.Error):
                print('Invalid packet!')
            except (ValueError, KeyError):
                print('Could not decrypt packet!')

    async def packet_send(self, packet: Packable):
        content = packet.pack()
        await self.channel.send("", file=discord.File(io.BytesIO(content),
                                                      f'{SHA256.new(content).hexdigest()[:8]}.bin'))
