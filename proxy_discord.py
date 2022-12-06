from __future__ import annotations

import abc
import asyncio
import binascii
import dataclasses
import enum
import io
import itertools
import os
import random
import struct
from asyncio import Queue
from collections import deque
from typing import Type

import base65536
import discord
import dotenv
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256

# using base65535, each message has 4000 bytes
# there are two bytes used for the port in Payload
# there are 32 bytes used for the Packet header
# there are 32 bytes used for the EncryptedPacket header

dotenv.load_dotenv()
AES_KEY = int(os.environ['AES_KEY'], 16).to_bytes(32, 'big', signed=False)


class Packable(abc.ABC):
    """
    An interface for a class that can be packed into and unpacked from bytes.
    """

    @abc.abstractmethod
    def __len__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def unpack(cls, packable: bytes):
        raise NotImplementedError


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
class Packet(Packable):
    """
    A packet has the following format. All values are stored in network order (big-endian).

    - source address: unsigned 32-bit integer (4 bytes)
    - destination address: unsigned 32-bit integer (4 bytes)
    - client port: unsigned 16-bit integer (2 bytes)
    - flags: unsigned 16-bit integer (2 bytes)
    - payload: bytes
    """
    src: int = 0  # uint32 / unsigned long / L
    dst: int = 0  # uint32 / unsigned long / L
    port: int = 0  # uint16 / unsigned short / H
    flags: PacketFlag = PacketFlag(0)  # uint16 / unsigned short / H
    payload: bytes = b''

    HEADER_FORMAT = '!LLHH'
    HEADER_LEN = struct.calcsize(HEADER_FORMAT)

    def __len__(self):
        return Packet.HEADER_LEN + len(self.payload)

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


class PackableEncrypted(Packable):
    """
    An encrypted packable has the following format.

    - nonce: 16 bytes
    - tag: 16 bytes
    - ciphertext: encrypted bytes of the underlying packable
    """
    ENC_HEADER_FORMAT = '!16s16s'
    ENC_HEADER_LEN = struct.calcsize(ENC_HEADER_FORMAT)

    def __len__(self):
        return self.ENC_HEADER_LEN + super().__len__()

    def pack(self) -> bytes:
        packet = super().pack()
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        # print(cipher.nonce.hex(), tag.hex(), ciphertext.hex())
        enc_packet = bytearray(self.ENC_HEADER_LEN)
        struct.pack_into(self.ENC_HEADER_FORMAT, enc_packet, 0, cipher.nonce, tag)
        enc_packet += ciphertext
        # print(enc_packet.hex())
        return bytes(enc_packet)

    @classmethod
    def unpack(cls, packet: bytes):
        nonce, tag = struct.unpack_from(cls.ENC_HEADER_FORMAT, packet, 0)
        ciphertext = packet[cls.ENC_HEADER_LEN:]
        # print(nonce, tag, ciphertext)
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return super().unpack(plaintext)


class PacketEncrypted(PackableEncrypted, Packet):
    """
    An encrypted packet. See PackableEncrypted and Packet for more information.
    """
    HEADER_LEN = PackableEncrypted.ENC_HEADER_LEN + Packet.HEADER_LEN


@dataclasses.dataclass(frozen=True)
class PacketBundle(Packable):
    """
    A bundle has the following format. All values are stored in network order (big-endian).

    - array of packet indices: any number of unsigned 32-bit integers (4 bytes each)
        these represent the starting index for each packet within
    - packet payloads: any number of byte strings, matching the indices specified
    """
    packets: list[Packable] = dataclasses.field(default_factory=list)

    HEADER_INDEX_FORMAT = 'L'
    HEADER_INDEX_LEN = struct.calcsize(HEADER_INDEX_FORMAT)

    def __len__(self):
        return self.HEADER_INDEX_LEN * len(self.packets) + sum(len(p) for p in self.packets)

    def pack(self) -> bytes:
        count = len(self.packets) + 1
        payload = [p.pack() for p in self.packets]
        header = bytearray(count * self.HEADER_INDEX_LEN)
        for x, i in enumerate(itertools.accumulate((len(p) for p in payload), initial=self.HEADER_INDEX_LEN * count)):
            struct.pack_into('!L', header, x * self.HEADER_INDEX_LEN, i)
        return b''.join(itertools.chain([bytes(header)], payload))

    @classmethod
    def unpack(cls, bundle: bytes, *, packet_type: Type[Packable] = Packet) -> PacketBundle:
        header_len = struct.unpack_from('!L', bundle, 0)[0]
        header = [i[0] for i in struct.iter_unpack('!L', bundle[:header_len])]
        packets = [packet_type.unpack(bundle[start:end]) for start, end in itertools.pairwise(header)]
        return cls(packets)


class PacketBundleEncrypted(PackableEncrypted, PacketBundle):
    """
    An encrypted bundle. See PackableEncrypted and PacketBundle for more information.
    """


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
