import unittest

from iotauth import (
    AuthConnectionError,
    IoTSPFrame,
    MessageType,
    SerializationError,
    recv_frame,
    serialize_frame,
    send_frame,
)


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = []

    def recv(self, size):
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, data):
        self.sent.append(data)


class TCPTransportTests(unittest.TestCase):
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
    unittest.main()
