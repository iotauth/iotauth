"""Binary serialization helpers for IoTAuth protocol data."""

from __future__ import annotations

from collections.abc import Buffer

from .exceptions import SerializationError

MAX_VARINT_BYTES = 5
MAX_VARINT_VALUE = 0xFFFFFFFF


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer using IoTAuth variable-length encoding."""

    if value < 0:
        raise SerializationError("Variable-length integer must not be negative")
    if value > MAX_VARINT_VALUE:
        raise SerializationError(f"Variable-length integer exceeds {MAX_VARINT_VALUE}")

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
                raise SerializationError(f"Variable-length integer exceeds {MAX_VARINT_VALUE}")
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
