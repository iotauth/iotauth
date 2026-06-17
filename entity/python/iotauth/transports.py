"""TCP helpers for reading and writing IoTSP frames."""

from __future__ import annotations

import socket
from typing import Any

from .exceptions import AuthConnectionError, SerializationError
from .protocol import IoTSPFrame, message_type_from_byte
from .serialization import decode_varint, encode_varint, MAX_VARINT_BYTES


DEFAULT_MAX_PAYLOAD_SIZE = 65536


def connect(host: str, port: int, *, timeout: float | None = 5.0) -> socket.socket:
    """Open a TCP connection to an IoTAuth peer."""

    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise AuthConnectionError(
            f"Could not connect to {host}:{port}: {exc}"
        ) from exc


def send_frame(sock: Any, frame: IoTSPFrame) -> None:
    """Send one complete IoTSP frame to a stream socket."""

    from .protocol import serialize_frame

    try:
        sock.sendall(serialize_frame(frame))
    except OSError as exc:
        raise AuthConnectionError(f"Could not send IoTSP frame: {exc}") from exc


def recv_frame(
    sock: Any, *, max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE
) -> IoTSPFrame:
    """Read one complete IoTSP frame from a stream socket."""

    if max_payload_size < 0:
        raise SerializationError("max_payload_size must not be negative")

    message_type_raw = _recv_exact(sock, 1)
    message_type = message_type_from_byte(message_type_raw[0])

    length_bytes = bytearray()
    for _ in range(MAX_VARINT_BYTES):
        next_byte = _recv_exact(sock, 1)
        length_bytes.extend(next_byte)
        if next_byte[0] & 0x80 == 0:
            payload_length, consumed = decode_varint(length_bytes)
            if consumed != len(length_bytes):
                raise SerializationError("IoTSP frame length used trailing bytes")
            if payload_length > max_payload_size:
                raise SerializationError(
                    f"IoTSP payload length {payload_length} exceeds "
                    f"maximum {max_payload_size}"
                )
            payload = _recv_exact(sock, payload_length)
            return IoTSPFrame(message_type, payload)

    raise SerializationError("Variable-length integer is too long")


def close_socket(sock: Any) -> None:
    """Safely close a socket, ignoring errors."""

    close = getattr(sock, "close", None)
    if close is None:
        return
    try:
        close()
    except OSError:
        pass


def _recv_exact(sock: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            chunk = sock.recv(size - len(chunks))
        except OSError as exc:
            raise AuthConnectionError(f"Could not read from TCP socket: {exc}") from exc
        if chunk == b"":
            raise AuthConnectionError("TCP socket closed before a complete frame arrived")
        chunks.extend(chunk)
    return bytes(chunks)
