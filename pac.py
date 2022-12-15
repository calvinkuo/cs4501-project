from __future__ import annotations

import asyncio
import traceback
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from tcp_server import Server
from http_request import HTTPRequest

PAC_PORT = 51234


class PACServer(Server):
    async def client_connected(self, client_reader: StreamReader, client_writer: StreamWriter):
        # Get the client's port
        port = client_writer.get_extra_info('peername')[1]
        print(f'[{port}] PAC client connected')

        # Wait until a complete HTTP request is sent
        try:
            req: HTTPRequest = await asyncio.wait_for(HTTPRequest.from_reader(client_reader), timeout=15)
            print(f'[{port}] Got initial request: {bytes(req)!r}')
        except asyncio.TimeoutError:
            print(f'[{port}] PAC client timed out')
            return
        except ConnectionResetError:
            print(f'[{port}] PAC client connection reset')
            return
        except asyncio.IncompleteReadError as e:
            print(f'[{port}] PAC client incomplete read, partial: {e.partial!r}')
            return
        except (EOFError, OSError):
            print(f'[{port}] PAC client error')
            print(traceback.format_exc())
            return

        if req.request_target.endswith('/proxy.pac'):
            with open('public/proxy.pac', 'rb') as f:
                body = f.read()
            # b'Cache-Control: max-age=5, must-revalidate\r\n' \
            res = b'HTTP/1.1 200 OK\r\n' \
                  b'Content-Type: application/x-ns-proxy-autoconfig\r\n' \
                  b'Content-Length: ' + str(len(body)).encode('ascii') + b'\r\n' \
                  b'\r\n' + body
        else:
            res = b'HTTP/1.1 404 Not Found\r\n\r\n'
        client_writer.write(res)
        print(f'[{port}] Sent to PAC client: {res!r}')
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        print(f'[{port}] Closed writer')


def make_pac(ip_address: str, port: int):
    Path('./public/').mkdir(parents=True, exist_ok=True)
    with open('./public/proxy.pac', 'w', encoding='utf-8') as f:
        f.write('\n'.join([
            'function FindProxyForURL(url, host) {',
           f'    if (isInNet(host, "{ip_address}", "255.255.255.255")) ' + '{',
           f'        return "DIRECT";',
            '    } else {',
           f'        return "PROXY {ip_address}:{port}";',
            '    }',
            '}',
        ]))


async def start():
    await PACServer(PAC_PORT).start()


if __name__ == '__main__':
    asyncio.run(start())
