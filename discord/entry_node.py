from __future__ import annotations

import asyncio
import os

import dotenv

import pac
from manager import DiscordPacketManager
from node import EntryNode
from packet import Packet
from tcp_server import Server, get_local_ip_address

ENTRY_PROXY_PORT = 60123


class DiscordEntryNode(EntryNode, Server):
    async def start(self):
        pac.make_pac(get_local_ip_address(), self.port)
        await asyncio.gather(pac.start(), super().start())

    async def packet_queue(self, packet: Packet):
        await bot.packet_queue(packet)


class EntryDiscordPacketManager(DiscordPacketManager):
    async def packet_receive(self, packet: Packet):
        await node.packet_receive(packet)


if __name__ == '__main__':
    dotenv.load_dotenv()
    loop = asyncio.new_event_loop()
    try:
        node = DiscordEntryNode(ENTRY_PROXY_PORT)
        bot = EntryDiscordPacketManager()
        asyncio.ensure_future(node.start(), loop=loop)
        asyncio.ensure_future(bot.start(os.environ['TOKEN']), loop=loop)
        loop.run_forever()
    finally:
        loop.close()
