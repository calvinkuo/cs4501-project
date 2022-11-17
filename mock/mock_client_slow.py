import asyncio

payload = b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n' \
          b'User-Agent: Python/3.10 aiohttp/3.8.3\r\n\r\n'


async def main():
    s = [await asyncio.open_connection('127.0.0.1', 9999) for _ in range(1)]
    for i in payload:
        print(repr(bytes([i]))[2:-1], end='')
        for reader, writer in s:
            writer.write(bytes([i]))
            await writer.drain()
        await asyncio.sleep(0.1)
    print()
    for reader, writer in s:
        data = await reader.read(8192)
        print(data)
    # with open('test.html', 'wb') as f:
    #     f.write(data)
    # print(await reader2.read(8192))
    await asyncio.sleep(100)
    # for reader, writer in s:
    #     writer.close()


if __name__ == '__main__':
    asyncio.run(main())


