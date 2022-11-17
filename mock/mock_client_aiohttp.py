import asyncio

import aiohttp


async def main():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://example.com/', proxy='http://127.0.0.1:9999') as r:
            print(await r.read())
        async with session.get('https://example.com/', proxy='http://127.0.0.1:9999') as r2:
            print(await r2.read())


if __name__ == '__main__':
    asyncio.run(main())
