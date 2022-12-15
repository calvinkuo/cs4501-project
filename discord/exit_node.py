from __future__ import annotations

import asyncio
import os

import dotenv

from node import ExitNode
from packet import Packet
from manager import DiscordPacketManager


class DiscordExitNode(ExitNode):
    async def packet_queue(self, packet: Packet):
        await bot.packet_queue(packet)


class ExitDiscordPacketManager(DiscordPacketManager):
    async def packet_receive(self, packet: Packet):
        await node.packet_receive(packet)


if __name__ == '__main__':
    dotenv.load_dotenv()
    loop = asyncio.new_event_loop()
    try:
        node = DiscordExitNode()
        bot = ExitDiscordPacketManager()
        asyncio.ensure_future(bot.start(os.environ['TOKEN']), loop=loop)
        loop.run_forever()
    finally:
        loop.close()
