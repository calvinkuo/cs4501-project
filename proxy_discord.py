from __future__ import annotations

import asyncio
import binascii
import dataclasses
import enum
import os
import random
import struct

import base65536
import discord
import dotenv
from Cryptodome.Cipher import AES

HEADER_FORMAT = '!HHxxxxLLQQ'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class ProxyPacketFlags(enum.Flag):
    BGN = 0x0001
    END = 0x0002
    ACK = 0x0004
    _RESERVED_3 = 0x0008
    _RESERVED_4 = 0x0010
    _RESERVED_5 = 0x0020
    _RESERVED_6 = 0x0040
    _RESERVED_7 = 0x0080
    _RESERVED_8 = 0x0100
    _RESERVED_9 = 0x0200
    _RESERVED_A = 0x0400
    _RESERVED_B = 0x0800
    _RESERVED_C = 0x1000
    _RESERVED_D = 0x2000
    _RESERVED_E = 0x4000
    _RESERVED_F = 0x8000


@dataclasses.dataclass(frozen=True)
class ProxyPacket:
    """
    A packet has the following format. All values are stored in network order (big-endian).

    - length of payload: unsigned 16-bit integer (2 bytes)
    - flags: unsigned 16-bit integer (2 bytes)
    - (4 bytes of padding)
    - sequence number: unsigned 32-bit integer (4 bytes)
    - source address: unsigned 64-bit integer (8 bytes)
    - destination address: unsigned 64-bit integer (8 bytes)
    - payload: bytes
    """
    # _length: int  # uint16 / unsigned short / H
    flags: ProxyPacketFlags  # uint16 / unsigned short / H
    seq_num: int  # uint32 / unsigned long / L
    ack_num: int  # uint32 / unsigned long / L
    src: int  # uint64 / unsigned long long / Q
    dst: int  # uint64 / unsigned long long / Q
    payload: bytes = b''  # max length of 65535

    def pack(self) -> bytes:
        packet = bytearray(HEADER_SIZE)
        struct.pack_into(HEADER_FORMAT, packet, 0,
                         len(self.payload), self.flags.value, self.seq_num, self.ack_num, self.src, self.dst)
        packet += self.payload
        return bytes(packet)

    @classmethod
    def unpack(cls, packet: bytes) -> ProxyPacket:
        payload_length, flags, *fields = struct.unpack_from(HEADER_FORMAT, packet, 0)
        assert len(packet) == HEADER_SIZE + payload_length
        return cls(ProxyPacketFlags(flags), *fields, packet[HEADER_SIZE:])


class ProxyPacketEncrypted(ProxyPacket):
    def pack(self) -> bytes:
        packet = super().pack()
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        return b''.join([cipher.nonce, tag, ciphertext])

    @classmethod
    def unpack(cls, packet: bytes) -> ProxyPacket:
        nonce = packet[0:16]
        tag = packet[16:32]
        ciphertext = packet[32:]
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return super().unpack(plaintext)


class EntryDiscord(discord.Client):
    def __init__(self, **options):
        super().__init__(intents=discord.Intents(messages=True, guilds=True), **options)
        self.id = random.randrange(1, 2**64)
        self.channel = None

    async def on_ready(self):
        print(f'Logged in!')
        self.channel = self.get_channel(int(os.environ['CHANNEL_ID']))
        await self.send_packet(0, b'1', ProxyPacketFlags.BGN)

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            await self.callback(message.content)

    async def send_packet(self, dst: int, payload: bytes, flags: ProxyPacketFlags):
        packet = ProxyPacketEncrypted(flags, 0, 0, self.id, dst, payload)
        await self.channel.send(base65536.encode(packet.pack()))
        print('Sent', packet)

    async def callback(self, content: str):
        try:
            packet = ProxyPacketEncrypted.unpack(base65536.decode(content))
            if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
                print('Received', packet)
                if packet.payload:
                    value = int(packet.payload.decode('ascii'))
                    await asyncio.sleep(2)
                    await self.send_packet(packet.src, str(value + 1).encode('ascii'), ProxyPacketFlags.ACK)
        except (ValueError, KeyError):
            # could not decrypt packet
            pass
        except (struct.error, binascii.Error):
            # ignore invalid packets
            pass


if __name__ == '__main__':
    dotenv.load_dotenv()
    AES_KEY = int(os.environ['AES_KEY'], 16).to_bytes(32, 'big', signed=False)
    EntryDiscord().run(os.environ['TOKEN'])

