from __future__ import annotations

import abc
import dataclasses
import enum
import itertools
import os
import struct
from typing import Type

import dotenv
from Cryptodome.Cipher import AES

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

    Classes which inherit from this class should list this class first,
    so that the encryption/decryption wrap any implementations in the other superclass.
    """

    ENC_HEADER_FORMAT = '!16s16s'
    ENC_HEADER_LEN = struct.calcsize(ENC_HEADER_FORMAT)

    def __len__(self):
        return self.ENC_HEADER_LEN + super().__len__()

    def pack(self) -> bytes:
        packet = super().pack()
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        enc_packet = bytearray(self.ENC_HEADER_LEN)
        struct.pack_into(self.ENC_HEADER_FORMAT, enc_packet, 0, cipher.nonce, tag)
        enc_packet += ciphertext
        return bytes(enc_packet)

    @classmethod
    def unpack(cls, packet: bytes):
        nonce, tag = struct.unpack_from(cls.ENC_HEADER_FORMAT, packet, 0)
        ciphertext = packet[cls.ENC_HEADER_LEN:]
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return super().unpack(plaintext)


@dataclasses.dataclass(frozen=True)
class PacketEncrypted(PackableEncrypted, Packet):
    """
    An encrypted packet. See PackableEncrypted and Packet for more information.
    """
    HEADER_LEN = PackableEncrypted.ENC_HEADER_LEN + Packet.HEADER_LEN


@dataclasses.dataclass(frozen=True)
class PacketBundle(Packable):
    """
    A bundle has the following format. All values are stored in network order (big-endian).

    - array of packet indices: one or more unsigned 32-bit integers (4 bytes each)
      these represent the starting and ending indices for each packet within
    - packet payloads: one or more byte strings, matching the indices specified
    
    If a bundle has three packets of length 16, then the bundle would be laid out as follows::

        0x00: 00 00 00 10 | 00 00 00 20 | 00 00 00 30 | 00 00 00 40
        0x10: xx xx xx xx | xx xx xx xx | xx xx xx xx | xx xx xx xx
        0x20: yy yy yy yy | yy yy yy yy | yy yy yy yy | yy yy yy yy
        0x30: zz zz zz zz | zz zz zz zz | zz zz zz zz | zz zz zz zz
        0x40: [EOF]

    Since the indices can be at most ``2 ** 32 - 1``, the maximum size of a packet bundle is 4 GB.
    """

    packets: list[Packet] = dataclasses.field(default_factory=list)

    HEADER_INDEX_FORMAT = '!L'
    HEADER_INDEX_LEN = struct.calcsize(HEADER_INDEX_FORMAT)

    def __len__(self):
        return self.HEADER_INDEX_LEN * len(self.packets) + sum(len(p) for p in self.packets)

    def pack(self) -> bytes:
        count = len(self.packets) + 1
        payload = [p.pack() for p in self.packets]
        header = bytearray(count * self.HEADER_INDEX_LEN)
        for x, i in enumerate(itertools.accumulate((len(p) for p in payload), initial=self.HEADER_INDEX_LEN * count)):
            struct.pack_into(self.HEADER_INDEX_FORMAT, header, x * self.HEADER_INDEX_LEN, i)
        return b''.join(itertools.chain([bytes(header)], payload))

    @classmethod
    def unpack(cls, bundle: bytes, *, packet_type: Type[Packable] = Packet) -> PacketBundle:
        header_len = struct.unpack_from(cls.HEADER_INDEX_FORMAT, bundle, 0)[0]
        header = [i[0] for i in struct.iter_unpack(cls.HEADER_INDEX_FORMAT, bundle[:header_len])]
        packets = [packet_type.unpack(bundle[start:end]) for start, end in itertools.pairwise(header)]
        return cls(packets)


@dataclasses.dataclass(frozen=True)
class PacketBundleEncrypted(PackableEncrypted, PacketBundle):
    """
    An encrypted bundle. See PackableEncrypted and PacketBundle for more information.

    This differs from a bundle of encrypted packets in that all of the packets in
    an encrypted bundle are encrypted together.
    """
