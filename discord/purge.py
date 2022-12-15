from __future__ import annotations

import os

import discord
import dotenv


class PurgeClient(discord.Client):
    async def on_ready(self):
        print(f'Logged in!')
        channel = self.get_channel(int(os.environ['CHANNEL_ID']))
        i = 0
        while h := channel.history(limit=100, oldest_first=False):
            messages = [m async for m in h if m.author.id == self.user.id]
            if not messages:
                break
            print(f"Purging... ({i})")
            await channel.delete_messages(messages)
            i += 1
        print("Done!")
        await self.close()


if __name__ == '__main__':
    dotenv.load_dotenv()
    PurgeClient(intents=discord.Intents.default()).run(os.environ['TOKEN'])

