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

# using base65535, each message has 4000 bytes
# there are two bytes used for the port in Payload
# there are 32 bytes used for the Packet header
# there are 32 bytes used for the EncryptedPacket header

dotenv.load_dotenv()
AES_KEY = int(os.environ['AES_KEY'], 16).to_bytes(32, 'big', signed=False)


class PacketFlag(enum.Flag):
    BGN = 0x0001
    END = 0x0002
    _RESERVED_2 = 0x0004
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

    - source address: unsigned 32-bit integer (4 bytes)
    - destination address: unsigned 32-bit integer (4 bytes)
    - client port: unsigned 16-bit integer (2 bytes)
    - flags: unsigned 16-bit integer (2 bytes)
    - payload: bytes
    """
    HEADER_FORMAT = '!LLHH'
    HEADER_LEN = struct.calcsize(HEADER_FORMAT)

    src: int = 0  # uint32 / unsigned long / L
    dst: int = 0  # uint32 / unsigned long / L
    port: int = 0  # uint16 / unsigned short / H
    flags: PacketFlag = PacketFlag(0)  # uint16 / unsigned short / H
    payload: bytes = b''

    def pack(self) -> bytes:
        packet = bytearray(Packet.HEADER_LEN)
        # print(self.src, self.dst, self.port, self.flags.value)
        struct.pack_into(Packet.HEADER_FORMAT, packet, 0, self.src, self.dst, self.port, self.flags.value)
        packet += self.payload
        return bytes(packet)

    @classmethod
    def unpack(cls, packet: bytes) -> Packet:
        *fields, flags = struct.unpack_from(Packet.HEADER_FORMAT, packet, 0)
        return cls(*fields, PacketFlag(flags), packet[Packet.HEADER_LEN:])


class PacketEncrypted(Packet):
    """
    An encrypted packet has the following format.

    - nonce: 16 bytes
    - tag: 16 bytes
    - ciphertext: encrypted bytes of the underlying packet
    """
    ENC_HEADER_FORMAT = '!16s16s'
    ENC_HEADER_LEN = struct.calcsize(ENC_HEADER_FORMAT)
    HEADER_LEN = ENC_HEADER_LEN + Packet.HEADER_LEN

    def pack(self) -> bytes:
        packet = super().pack()
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        # print(cipher.nonce, tag, ciphertext)
        enc_packet = bytearray(self.ENC_HEADER_LEN)
        struct.pack_into(self.ENC_HEADER_FORMAT, enc_packet, 0, cipher.nonce, tag)
        enc_packet += ciphertext
        # print(enc_packet)
        return bytes(enc_packet)

    @classmethod
    def unpack(cls, packet: bytes) -> Packet:
        nonce, tag = struct.unpack_from(cls.ENC_HEADER_FORMAT, packet, 0)
        ciphertext = packet[cls.ENC_HEADER_LEN:]
        # print(nonce, tag, ciphertext)
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return super().unpack(plaintext)


class DiscordBot(discord.Client, abc.ABC):
    MAX_MSG_LEN = 2000
    READ_SIZE = MAX_MSG_LEN * 2 - PacketEncrypted.HEADER_LEN

    def __init__(self, **options):
        super().__init__(intents=discord.Intents(messages=True, guilds=True), **options)
        self.id = random.randrange(1, 2 ** 32)
        self.channel: discord.TextChannel | None = None

    async def on_ready(self):
        print(f'Logged in!')
        self.channel = self.get_channel(int(os.environ['CHANNEL_ID']))

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            try:
                packet = PacketEncrypted.unpack(base65536.decode(message.content))
                if packet.src != self.id and (packet.dst == self.id or packet.dst == 0):
                    await self.callback(packet)
            except (struct.error, binascii.Error):
                print('Invalid packet!')
            except (ValueError, KeyError):
                print('Could not decrypt packet!')

    async def send_packet(self, dst: int, port: int, *, flags: PacketFlag = PacketFlag(0), payload: bytes = b''):
        packet = PacketEncrypted(self.id, dst, port, flags, payload)
        content = base65536.encode(packet.pack())
        if len(content) > 2000:
            print("Error: content is too long", len(content))
        await self.channel.send(content)
        print('Sent', packet)

    async def callback(self, packet: Packet):
        raise NotImplementedError
