"""Binary serialization helpers for IoTAuth protocol frames."""

from __future__ import annotations

from collections.abc import Buffer

from ..exceptions import SerializationError
from ..messages import IoTSPFrame, message_type_from_byte


MAX_VARINT_BYTES = 5
MAX_VARINT_VALUE = 0xFFFFFFFF


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer using IoTAuth variable-length encoding."""

    if value < 0:
        raise SerializationError("Variable-length integer must not be negative")
    if value > MAX_VARINT_VALUE:
        raise SerializationError(
            f"Variable-length integer exceeds {MAX_VARINT_VALUE}"
        )

    encoded = bytearray()
    while value > 127:
        encoded.append(0x80 | (value & 0x7F))
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def decode_varint(data: Buffer, offset: int = 0) -> tuple[int, int]:
    """Decode an IoTAuth variable-length integer.

    Returns:
        A ``(value, bytes_consumed)`` tuple.
    """

    view = memoryview(data)
    if offset < 0 or offset >= len(view):
        raise SerializationError("Variable-length integer offset is out of range")

    value = 0
    for index in range(MAX_VARINT_BYTES):
        position = offset + index
        if position >= len(view):
            raise SerializationError("Truncated variable-length integer")

        byte = view[position]
        value |= (byte & 0x7F) << (7 * index)
        if byte & 0x80 == 0:
            if value > MAX_VARINT_VALUE:
                raise SerializationError(
                    f"Variable-length integer exceeds {MAX_VARINT_VALUE}"
                )
            return value, index + 1

    raise SerializationError("Variable-length integer is too long")


def encode_uint_be(value: int, length: int) -> bytes:
    """Encode an unsigned integer into a fixed-width big-endian byte string."""

    if length < 1:
        raise SerializationError("Integer byte length must be at least 1")
    if value < 0:
        raise SerializationError("Unsigned integer must not be negative")
    max_value = (1 << (8 * length)) - 1
    if value > max_value:
        raise SerializationError(
            f"Value {value} does not fit in {length} unsigned big-endian bytes"
        )
    return value.to_bytes(length, "big")


def decode_uint_be(data: Buffer) -> int:
    """Decode a fixed-width unsigned big-endian integer."""

    view = memoryview(data)
    if len(view) < 1:
        raise SerializationError("Unsigned big-endian integer buffer is empty")
    return int.from_bytes(view, "big")


def serialize_frame(frame: IoTSPFrame) -> bytes:
    """Serialize an IoTSP frame as message type, payload length, and payload."""

    return bytes([int(frame.message_type)]) + encode_varint(len(frame.payload)) + frame.payload


def parse_frame(data: Buffer, *, allow_trailing: bool = False) -> IoTSPFrame:
    """Parse an IoTSP frame from bytes."""

    view = memoryview(data)
    if len(view) < 1:
        raise SerializationError("IoTSP frame is empty")

    message_type = message_type_from_byte(view[0])
    payload_length, length_size = decode_varint(view, 1)
    payload_start = 1 + length_size
    payload_end = payload_start + payload_length

    if payload_end > len(view):
        raise SerializationError(
            "IoTSP frame payload length exceeds available data"
        )
    if payload_end < len(view) and not allow_trailing:
        raise SerializationError("IoTSP frame contains trailing bytes")

    return IoTSPFrame(
        message_type=message_type,
        payload=bytes(view[payload_start:payload_end]),
    )
