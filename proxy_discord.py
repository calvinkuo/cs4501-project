from __future__ import annotations

import abc
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
DISCORD_MAX_MESSAGE_LENGTH = 2000
DISCORD_READ_SIZE = DISCORD_MAX_MESSAGE_LENGTH * 2 - 32 - 32 - 2
# using base65535, each message has 4000 bytes
# there are two bytes used for the port in Payload
# there are 32 bytes used for the Packet header
# there are 32 bytes used for the EncryptedPacket header

dotenv.load_dotenv()
AES_KEY = int(os.environ['AES_KEY'], 16).to_bytes(32, 'big', signed=False)


class PacketFlag(enum.Flag):
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
class Packet:
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
    flags: PacketFlag  # uint16 / unsigned short / H
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
    def unpack(cls, packet: bytes) -> Packet:
        payload_length, flags, *fields = struct.unpack_from(HEADER_FORMAT, packet, 0)
        assert len(packet) == HEADER_SIZE + payload_length
        return cls(PacketFlag(flags), *fields, packet[HEADER_SIZE:])


class PacketEncrypted(Packet):
    """
    An encrypted packet has the following format.

    - nonce: 16 bytes
    - tag: 16 bytes
    - ciphertext: encrypted bytes of the underlying packet
    """
    def pack(self) -> bytes:
        packet = super().pack()
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        return b''.join([cipher.nonce, tag, ciphertext])

    @classmethod
    def unpack(cls, packet: bytes) -> Packet:
        nonce = packet[0:16]
        tag = packet[16:32]
        ciphertext = packet[32:]
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return super().unpack(plaintext)


class DiscordBot(discord.Client, abc.ABC):
    def __init__(self, **options):
        super().__init__(intents=discord.Intents(messages=True, guilds=True), **options)
        self.id = random.randrange(1, 2 ** 64)
        self.channel = None

    async def on_ready(self):
        print(f'Logged in!')
        self.channel = self.get_channel(int(os.environ['CHANNEL_ID']))

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            try:
                packet = PacketEncrypted.unpack(base65536.decode(message.content))
                if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
                    await self.callback(packet)
            except (ValueError, KeyError):
                # could not decrypt packet
                pass
            except (struct.error, binascii.Error):
                # ignore invalid packets
                pass

    async def send_packet(self, dst: int, payload: bytes, flags: PacketFlag = PacketFlag(0)):
        packet = PacketEncrypted(flags, 0, 0, self.id, dst, payload)
        content = base65536.encode(packet.pack())
        if len(content) > 2000:
            print("Error: content is too long", len(content))
        await self.channel.send(content)
        print('Sent', packet)

    async def callback(self, packet: Packet):
        raise NotImplementedError
