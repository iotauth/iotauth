"""Tests for wire-level serialization and transport helpers."""

import unittest

from iotauth import (
    AuthConnectionError,
    IoTSPFrame,
    MessageType,
    SerializationError,
    decode_uint_be,
    decode_varint,
    encode_uint_be,
    encode_varint,
    parse_frame,
    recv_frame,
    send_frame,
    serialize_frame,
)
from tests.helpers import FakeSocket


class VarintTests(unittest.TestCase):
    """Tests for variable-length integer encoding."""

    def test_encodes_known_values(self):
        examples = {
            0: b"\x00",
            1: b"\x01",
            127: b"\x7f",
            128: b"\x80\x01",
            300: b"\xac\x02",
        }

        for value, encoded in examples.items():
            with self.subTest(value=value):
                self.assertEqual(encode_varint(value), encoded)
                self.assertEqual(decode_varint(encoded), (value, len(encoded)))

    def test_rejects_negative_varint(self):
        with self.assertRaisesRegex(SerializationError, "negative"):
            encode_varint(-1)

    def test_rejects_truncated_varint(self):
        with self.assertRaisesRegex(SerializationError, "Truncated"):
            decode_varint(b"\x80")

    def test_rejects_too_long_varint(self):
        with self.assertRaisesRegex(SerializationError, "too long"):
            decode_varint(b"\x80\x80\x80\x80\x80\x00")


class UnsignedBigEndianTests(unittest.TestCase):
    """Tests for fixed-length big-endian integer encoding."""

    def test_round_trips_common_lengths(self):
        examples = [
            (1, 1),
            (0x1234, 2),
            (0x12345678, 4),
            (0x123456789ABCDEF0, 8),
        ]

        for value, length in examples:
            with self.subTest(value=value, length=length):
                encoded = encode_uint_be(value, length)
                self.assertEqual(len(encoded), length)
                self.assertEqual(decode_uint_be(encoded), value)

    def test_rejects_value_too_large_for_length(self):
        with self.assertRaisesRegex(SerializationError, "does not fit"):
            encode_uint_be(256, 1)

    def test_rejects_negative_value(self):
        with self.assertRaisesRegex(SerializationError, "negative"):
            encode_uint_be(-1, 1)

    def test_rejects_empty_decode_buffer(self):
        with self.assertRaisesRegex(SerializationError, "empty"):
            decode_uint_be(b"")


class IoTSPFrameTests(unittest.TestCase):
    """Tests for IoTSP frame serialization and parsing."""

    def test_serializes_frame_to_expected_bytes(self):
        frame = IoTSPFrame(MessageType.SECURE_COMM_MSG, b"abc")
        self.assertEqual(serialize_frame(frame), b"\x21\x03abc")

    def test_parses_frame_round_trip(self):
        frame = IoTSPFrame(MessageType.SKEY_HANDSHAKE_1, b"payload")
        parsed = parse_frame(serialize_frame(frame))
        self.assertEqual(parsed, frame)

    def test_rejects_empty_frame(self):
        with self.assertRaisesRegex(SerializationError, "empty"):
            parse_frame(b"")

    def test_rejects_unknown_message_type(self):
        with self.assertRaisesRegex(SerializationError, "Unknown"):
            parse_frame(b"\xff\x00")

    def test_rejects_payload_length_mismatch(self):
        with self.assertRaisesRegex(SerializationError, "exceeds"):
            parse_frame(b"\x21\x04abc")

    def test_rejects_trailing_bytes_by_default(self):
        with self.assertRaisesRegex(SerializationError, "trailing"):
            parse_frame(b"\x21\x03abcx")

    def test_can_allow_trailing_bytes(self):
        parsed = parse_frame(b"\x21\x03abcx", allow_trailing=True)
        self.assertEqual(parsed, IoTSPFrame(MessageType.SECURE_COMM_MSG, b"abc"))


class TCPTransportTests(unittest.TestCase):
    """Tests for reading and writing IoTSP frames over sockets."""

    def test_recv_frame_reads_fragmented_frame(self):
        frame = IoTSPFrame(MessageType.SECURE_COMM_MSG, b"a" * 130)
        sock = FakeSocket(serialize_frame(frame))
        parsed = recv_frame(sock)
        self.assertEqual(parsed, frame)

    def test_recv_frame_rejects_oversized_payload(self):
        frame = IoTSPFrame(MessageType.SECURE_COMM_MSG, b"a" * 10)
        sock = FakeSocket(serialize_frame(frame))
        with self.assertRaisesRegex(SerializationError, "exceeds"):
            recv_frame(sock, max_payload_size=3)

    def test_recv_frame_rejects_early_close(self):
        sock = FakeSocket(b"\x21\x05ab")
        with self.assertRaisesRegex(AuthConnectionError, "closed"):
            recv_frame(sock)

    def test_send_frame_writes_serialized_frame(self):
        frame = IoTSPFrame(MessageType.AUTH_ALERT, b"\x01")
        sock = FakeSocket()
        send_frame(sock, frame)
        self.assertEqual(sock.sent, [serialize_frame(frame)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
