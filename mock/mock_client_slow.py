import asyncio

payload = b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
# payload = b'GET http://example.com/?test=' + (b'test' * (1024*1024)) + b' HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'  # long URL
# payload = b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nX-Test: ' + (b'test' * (1024*1024)) + b'\r\n\r\n'  # long header


async def main():
    s = [await asyncio.open_connection('127.0.0.1', 60123) for _ in range(200)]
    try:
        for i in payload:
            print(repr(bytes([i]))[2:-1], end='')
            for reader, writer in s:
                writer.write(bytes([i]))
                await writer.drain()
                if writer.is_closing():
                    break
            await asyncio.sleep(0.1)

        # for reader, writer in s:
        #     writer.write(payload)
        # for reader, writer in s:
        #     await writer.drain()
        #     if writer.is_closing():
        #         break
    except ConnectionError:
        pass
    print()
    for reader, writer in s:
        data = await reader.read()
        print(data)
    for reader, writer in s:
        writer.close()


if __name__ == '__main__':
    asyncio.run(main())


