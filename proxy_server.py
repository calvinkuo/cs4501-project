from __future__ import annotations

import asyncio
import collections
import random
import re
import socket
import traceback
from asyncio import StreamReader, StreamWriter
from typing import NamedTuple

NON_RESERVED_PORT_MIN = 49152
NON_RESERVED_PORT_MAX = 65535


# SOURCE: https://stackoverflow.com/a/166589
def get_local_ip_address() -> str:
    """Returns the proxy server's local IP address."""
    with socket.create_connection(('1.1.1.1', 80)) as s:
        return s.getsockname()[0]


class HTTPFieldName(str):
    """The name of an HTTP header field. Field names are case-insensitive."""
    def __eq__(self, other):
        return super().casefold().__eq__(other.casefold())


class HTTPField(NamedTuple):
    """An HTTP header field, consisting of a name and content."""
    name: HTTPFieldName
    content: str


class HTTPHeaders(collections.UserList[HTTPField]):
    """The headers of an HTTP message, consisting of a list of fields.

    Since "multiple message-header fields with the same field-name MAY be present in a message",
    it is stored as a list rather than a dictionary to allow for duplicate keys and preserve the original order."""
    header_regex = re.compile(rb"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):[ \t]+(.*)[ \t]*$")

    @classmethod
    def from_bytes(cls, data: list[bytes]) -> HTTPHeaders:
        """Returns a new ``HTTPHeaders`` instance populated from the given bytes."""
        headers = []
        for line in data:
            match = cls.header_regex.match(line.removesuffix(b'\r\n'))
            field_name: HTTPFieldName = HTTPFieldName(match.group(1).decode('ascii'))
            field_content: str = match.group(2).decode('latin1')
            headers.append(HTTPField(field_name, field_content))
        return cls(headers)

    def get(self, name: str) -> list[HTTPField]:
        """Returns a list of headers with the given ``name``."""
        return [header for header in self.data if header.name == name]

    def proxy(self) -> None:
        """Modifies the headers of the request for the next hop. Specifically, the ``Proxy-Connection`` header is
        dropped, any headers listed in the ``Connection`` header are dropped, and the ``Connection`` header is changed
        to the HTTP/1.1 default value of ``keep-alive``."""
        headers = []
        for field in self.data:
            if field.name == 'Proxy-Connection':
                continue
            elif field.name.casefold() in ','.join(v.strip(' \t') for _, v in self.get('Connection')).split(','):
                continue
            elif field.name == 'Connection':
                headers.append(HTTPField(HTTPFieldName('Connection'), 'keep-alive'))
            else:
                headers.append(field)
        self.data = headers


class HTTPRequest:
    """An HTTP request, consisting of a start line, headers, and a body."""
    _RE_START_LINE = re.compile(r"([!#$%&'*+\-.^_`|~0-9A-Za-z]+) (.+) (HTTP/\d\.\d)\r\n")
    _RE_HOST_PORT = re.compile(r'^(.+?)(?::(\d+))?$')

    def __init__(self, method: str, request_target: str, http_version: str, headers: HTTPHeaders, body: bytes):
        self.method = method
        self.request_target = request_target
        self.http_version = http_version
        self.headers = headers
        self.body = body

    @classmethod
    async def from_reader(cls, reader: StreamReader):
        """Returns an HTTPRequest instance, read from the provided StreamReader.
        Note that this method will not return until a complete request has been sent."""
        start_line = await reader.readuntil(b'\r\n')
        method, request_target, http_version = cls._RE_START_LINE.match(start_line.decode('ascii')).groups()

        raw_headers = []
        while (header := await reader.readuntil(b'\r\n')) and header.rstrip(b' \t\r\n') != b'':
            raw_headers.append(header)
        headers = HTTPHeaders.from_bytes(raw_headers)

        # If this request has `Transfer-Encoding: chunked`, the body continues until a chunk of length of 0.
        # If this request has a `Content-Length` header, the body will be the specified length in bytes.
        body = b''
        if any('chunked' in value.split(',') for key, value in headers.get('Transfer-Encoding')):
            body = await reader.readuntil(b'0\r\n\r\n')
        elif len(cl := headers.get('Content-Length')) > 0 \
                and (content_length := int(cl[0].content.split(',')[0].strip(' \t'))):
            body = await reader.readexactly(content_length)

        return cls(method, request_target, http_version, headers, body)

    @property
    def target(self) -> tuple[str, int]:
        """Returns a tuple consisting of the host and port that this request should be sent to."""
        if self.method == 'CONNECT':  # client is requesting SSL tunnel from proxy
            host, port = self._RE_HOST_PORT.match(self.request_target).groups()
            port = int(port) if port is not None else 443  # default TLS port
        else:
            host, port = self._RE_HOST_PORT.match(self.headers.get('Host')[0].content).groups()
            port = int(port) if port is not None else 80  # default HTTP port
        return host, port

    def __bytes__(self):
        return b''.join([f'{self.method} {self.request_target} {self.http_version}\r\n'.encode('ascii'),
                         b'\r\n'.join(f'{header.name}: {header.content}'.encode('latin1') for header in self.headers),
                         b'\r\n\r\n',
                         self.body])


class ProxyServer:
    def __init__(self, port: int = None):
        self.port = port if port is not None else random.randint(NON_RESERVED_PORT_MIN, NON_RESERVED_PORT_MAX)
        self.server = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.server.is_serving():
            await self.stop()

    async def start(self):
        """Starts the proxy server."""
        self.server = await asyncio.start_server(tunnel, '0.0.0.0', self.port, start_serving=True)
        print(f'Proxy server running on {get_local_ip_address()}:{self.port}')
        try:
            await self.server.serve_forever()
        except asyncio.exceptions.CancelledError:
            print(f'Proxy server task was canceled')

    async def stop(self):
        """Stops the proxy server."""
        print(f'Stopping proxy server')
        self.server.close()
        await self.server.wait_closed()
        print(f'Closed proxy server')


async def tunnel(client_reader: StreamReader, client_writer: StreamWriter):
    """Creates a tunnel between the client and the server it requests to connect to.
    This method runs until either the client or the server closes the connection."""
    # Get the client's port
    port = client_writer.get_extra_info('peername')[1]
    print(f'[{port}] Client connected')

    # Wait until a complete HTTP request is sent
    try:
        req = await asyncio.wait_for(HTTPRequest.from_reader(client_reader), timeout=30)
        print(f'[{port}] Got initial request: {bytes(req)!r}')
    except asyncio.TimeoutError:
        print(f'[{port}] Client timed out')
        return
    except ConnectionResetError:
        print(f'[{port}] Client connection reset')
        return
    except (EOFError, OSError):
        print(f'[{port}] Client error')
        print(traceback.format_exc())
        return
    req.headers.proxy()

    # Open a connection to the server specified in the request
    try:
        server_reader, server_writer = await asyncio.wait_for(asyncio.open_connection(*req.target), timeout=30)
        print(f'[{port}] Connected to server')
    except asyncio.TimeoutError:
        print(f'[{port}] Server timed out')
        return
    except (EOFError, OSError):
        print(f'[{port}] Server error')
        print(traceback.format_exc())
        return

    # If using HTTPS tunneling, respond to client with 200 OK so that it can begin TLS negotiation
    if req.method == 'CONNECT':
        res = b'HTTP/1.1 200 OK\r\n\r\n'
        client_writer.write(res)
        print(f'[{port}] Sent to client: {res!r}')
    # Otherwise, send the initial request to the server directly
    else:
        server_writer.write(bytes(req))
        print(f'[{port}] Sent to server: {bytes(req)!r}')

    # Continue piping messages back-and-forth until one of the connections is closed
    done, pending = await asyncio.wait([
            asyncio.create_task(pipe_client_to_server(port, client_reader, server_writer)),
            asyncio.create_task(pipe_server_to_client(port, server_reader, client_writer))
        ], return_when=asyncio.FIRST_COMPLETED)
    for future in pending:
        future.cancel()
    print(f'[{port}] Tunnel finished')


async def pipe_client_to_server(port: int, client_reader: StreamReader, server_writer: StreamWriter):
    """Pipes data from the client to server."""
    try:
        while True:
            client_data = await asyncio.wait_for(client_reader.read(4096), timeout=30)
            if not client_data:
                print(f'[{port}] Client reached EOF')
                break
            # print(f'[{port}] Sent to server: {client_data!r}')
            print(f'[{port}] Sent {len(client_data)} bytes to server')
            server_writer.write(client_data)
            await server_writer.drain()
    except asyncio.TimeoutError:
        print(f'[{port}] Client timed out')
    except ConnectionResetError:
        print(f'[{port}] Client connection reset')
    except (EOFError, OSError):
        print(f'[{port}] Client error')
        print(traceback.format_exc())


async def pipe_server_to_client(port: int, server_reader: StreamReader, client_writer: StreamWriter):
    """Pipes data from the server to client."""
    try:
        while True:
            server_data = await asyncio.wait_for(server_reader.read(4096), timeout=30)
            if not server_data:
                print(f'[{port}] Server reached EOF')
                break
            # print(f'[{port}] Sent to client: {server_data!r}')
            print(f'[{port}] Sent {len(server_data)} bytes to client')
            client_writer.write(server_data)
            await client_writer.drain()
    except asyncio.TimeoutError:
        print(f'[{port}] Server timed out')
    except ConnectionResetError:
        print(f'[{port}] Server connection reset')
    except (EOFError, OSError):
        print(f'[{port}] Server error')
        print(traceback.format_exc())


if __name__ == '__main__':
    asyncio.run(ProxyServer(9999).start())