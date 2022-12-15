import asyncio
import timeit

import aiohttp


async def main():
    for _ in range(3):
        async with aiohttp.ClientSession() as session:
            start = timeit.default_timer()
            async with session.get('https://example.com/', proxy='http://127.0.0.1:60123') as r:
                data = await r.read()
            end = timeit.default_timer()
            # print(data)
            print(f'Took {end - start} seconds for {len(data)} bytes')


if __name__ == '__main__':
    asyncio.run(main())
