from __future__ import annotations

import asyncio
import collections
import re
from asyncio import StreamReader
from typing import NamedTuple


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


class HTTPError(ValueError):
    """An HTTP error response."""
    def __init__(self, code: int, reason: str):
        super().__init__()
        self.code: int = code
        self.reason: str = reason
        self.res: bytes = f'HTTP/1.1 {self.code} {self.reason}\r\nConnection: close\r\n\r\n'.encode('ascii')


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

    @staticmethod
    async def _read_until(reader: StreamReader, separator: bytes, limit: int = 0) -> bytes:
        buffer: list[bytes] = []
        while True:
            try:
                buffer.append(await reader.readuntil(separator))
                break
            except asyncio.LimitOverrunError as e:
                buffer.append(await reader.readexactly(e.consumed))
                if limit and len(buffer) > limit:
                    break
        return b''.join(buffer)

    @classmethod
    async def from_reader(cls, reader: StreamReader, limit: int = 0, *, header_only: bool = True):
        """Returns an HTTPRequest instance, read from the provided StreamReader.
        Note that this method will not return until a complete request has been sent."""
        start_line = await cls._read_until(reader, b'\r\n', limit)
        if limit and len(start_line) > limit:
            raise HTTPError(414, 'URI Too Long')
        method, request_target, http_version = cls._RE_START_LINE.match(start_line.decode('ascii')).groups()

        raw_headers = []
        while (header := await cls._read_until(reader, b'\r\n', limit)) and header.rstrip(b' \t\r\n') != b'':
            raw_headers.append(header)
        if limit and len(start_line) + sum(len(header) for header in raw_headers) > limit:
            raise HTTPError(431, 'Request Header Fields Too Large')
        headers = HTTPHeaders.from_bytes(raw_headers)

        if header_only:
            body = None
        else:
            body = b''
            # If this request has `Transfer-Encoding: chunked`, the body continues until a chunk of length of 0.
            if any('chunked' in value.split(',') for key, value in headers.get('Transfer-Encoding')):
                chunks = []
                while True:
                    chunk_length = int((await cls._read_until(reader, b'\r\n')).removeprefix(b'\r\n').decode('ascii'), 16)
                    chunk = await reader.readexactly(chunk_length)
                    if await reader.readexactly(2) != b'\r\n':
                        raise HTTPError(400, 'Bad Request')
                    if chunk_length == 0:
                        break
                    chunks.append(chunk)
                body = b''.join(chunks)
            # If this request has a `Content-Length` header, the body will be the specified length in bytes.
            elif len(cl := headers.get('Content-Length')) > 0 \
                    and (content_length := int(cl[0].content.split(',')[0].strip(' \t'))):
                body = await reader.readexactly(content_length)
            if limit and len(start_line) + sum(len(header) for header in raw_headers) + len(body) > limit:
                raise HTTPError(413, 'Content Too Large')

        return cls(method, request_target, http_version, headers, body)

    @classmethod
    def from_bytes(cls, buf: bytes, *, header_only: bool = True):
        """Returns an HTTPRequest instance from the provided bytes instance."""
        i = buf.find(b'\r\n')
        start_line, buf = buf[:i+2], buf[i+2:]
        method, request_target, http_version = cls._RE_START_LINE.match(start_line.decode('ascii')).groups()

        raw_headers = []
        i = buf.find(b'\r\n')
        header, buf = buf[:i+2], buf[i+2:]
        while header.rstrip(b' \t\r\n') != b'':
            raw_headers.append(header)
            i = buf.find(b'\r\n')
            header, buf = buf[:i+2], buf[i+2:]
        headers = HTTPHeaders.from_bytes(raw_headers)

        if header_only:
            body = None
        else:
            body = buf

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
        """Returns the HTTPRequest encoded as bytes."""
        return b''.join([f'{self.method} {self.request_target} {self.http_version}\r\n'.encode('ascii'),
                         b'\r\n'.join(f'{header.name}: {header.content}'.encode('latin1') for header in self.headers),
                         b'\r\n\r\n',
                         self.body if self.body is not None else b''])
