import unittest
from unittest.mock import patch

from iotauth import (
    AuthConnectionError,
    AuthInfo,
    EntityConfig,
    EntityInfo,
    ExpiredKeyError,
    InvalidSequenceNumberError,
    IoTAuthContext,
    IoTSPFrame,
    MessageIntegrityError,
    MessageType,
    SecureChannelClosed,
    SecureChannel,
    SecureHandshakeError,
    SerializationError,
    SessionConfig,
    SessionKey,
    SessionKeyCache,
    TargetServer,
    accept_secure,
    connect_secure,
    parse_frame,
    serialize_frame,
    session_key_is_expired,
    symmetric_encrypt_authenticate,
    symmetric_decrypt_authenticate,
)
from iotauth.secure_channel import (
    MAX_SEQUENCE_NUMBER,
    _parse_secure_message,
    _serialize_secure_message,
)


CLIENT_NONCE = b"c" * 8


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.closed = False
        self.timeout = None

    def recv(self, size):
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


class FailingSendSocket(FakeSocket):
    def sendall(self, data):
        raise OSError("write failed")


def socket_factory_for(fake_socket):
    def factory(host, port, timeout):
        fake_socket.opened_with = (host, port, timeout)
        return fake_socket

    return factory


def session_key(abs_validity=0xFFFFFFFFFFFF):
    return SessionKey(
        id=b"12345678",
        cipher_key=b"k" * 16,
        mac_key=b"m" * 32,
        abs_validity=abs_validity,
        rel_validity=60000,
        encryption_mode="AES_128_CBC",
        hmac_enabled=True,
        permanent_distribution_key=False,
    )


def context(targets=None):
    return IoTAuthContext(
        config=EntityConfig(
            entity=EntityInfo(name="net1.client", private_key_path=None),
            auth=AuthInfo(
                id=101,
                host="127.0.0.1",
                port=21900,
                public_key_path=None,
            ),
            session=SessionConfig(
                protocol="TCP",
                encryption_mode="AES_128_CBC",
                distribution_encryption_mode="AES_128_CBC",
            ),
            purposes=[{"group": "Servers"}],
            num_keys=1,
            targets=targets
            if targets is not None
            else [TargetServer(host="127.0.0.1", port=21100)],
        ),
        auth_public_key=None,
        entity_private_key=None,
        distribution_key=None,
        session_keys=SessionKeyCache(),
    )


def context_with_key(key):
    ctx = context()
    ctx.session_keys.add(key)
    return ctx


def frame(message_type, payload):
    return serialize_frame(IoTSPFrame(message_type, payload))


class SecureChannelTests(unittest.TestCase):
    def test_session_key_expiration_uses_epoch_milliseconds(self):
        key = session_key(abs_validity=1000)

        self.assertFalse(session_key_is_expired(key, now_ms=999))
        self.assertTrue(session_key_is_expired(key, now_ms=1000))

    def test_connect_secure_completes_client_handshake(self):
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_2, b"handshake2"))
        key = session_key()

        with patch(
            "iotauth.secure_channel.build_handshake_1",
            return_value=b"handshake1",
        ) as build_h1, patch(
            "iotauth.secure_channel.verify_handshake_2_and_build_handshake_3",
            return_value=(b"s" * 8, b"handshake3"),
        ) as verify_h2:
            channel = connect_secure(
                context(),
                key=key,
                _socket_factory=socket_factory_for(fake),
                _nonce_factory=lambda size: CLIENT_NONCE,
            )

        self.assertIsInstance(channel, SecureChannel)
        self.assertIs(channel.socket, fake)
        self.assertIs(channel.session_key, key)
        self.assertEqual(channel.send_sequence, 0)
        self.assertEqual(channel.receive_sequence, 0)
        self.assertFalse(channel.closed)
        self.assertEqual(fake.opened_with, ("127.0.0.1", 21100, 5.0))
        build_h1.assert_called_once_with(key, CLIENT_NONCE)
        verify_h2.assert_called_once_with(key, b"handshake2", CLIENT_NONCE)

        sent_1 = parse_frame(fake.sent[0])
        sent_3 = parse_frame(fake.sent[1])
        self.assertEqual(sent_1, IoTSPFrame(MessageType.SKEY_HANDSHAKE_1, b"handshake1"))
        self.assertEqual(sent_3, IoTSPFrame(MessageType.SKEY_HANDSHAKE_3, b"handshake3"))
        self.assertFalse(fake.closed)

    def test_connect_secure_allows_host_port_override(self):
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_2, b"handshake2"))

        with patch(
            "iotauth.secure_channel.build_handshake_1",
            return_value=b"handshake1",
        ), patch(
            "iotauth.secure_channel.verify_handshake_2_and_build_handshake_3",
            return_value=(b"s" * 8, b"handshake3"),
        ):
            connect_secure(
                context(),
                key=session_key(),
                host="example.test",
                port=12345,
                timeout=1.5,
                _socket_factory=socket_factory_for(fake),
                _nonce_factory=lambda size: CLIENT_NONCE,
            )

        self.assertEqual(fake.opened_with, ("example.test", 12345, 1.5))
        self.assertEqual(fake.timeout, 1.5)

    def test_wrong_response_message_type_raises_handshake_error(self):
        fake = FakeSocket(frame(MessageType.AUTH_ALERT, b"\x01"))

        with patch(
            "iotauth.secure_channel.build_handshake_1",
            return_value=b"handshake1",
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "SKEY_HANDSHAKE_2"):
                connect_secure(
                    context(),
                    key=session_key(),
                    _socket_factory=socket_factory_for(fake),
                    _nonce_factory=lambda size: CLIENT_NONCE,
                )

        self.assertTrue(fake.closed)

    def test_nonce_mismatch_closes_socket_and_raises(self):
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_2, b"handshake2"))

        with patch(
            "iotauth.secure_channel.build_handshake_1",
            return_value=b"handshake1",
        ), patch(
            "iotauth.secure_channel.verify_handshake_2_and_build_handshake_3",
            side_effect=SecureHandshakeError("nonce mismatch"),
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "nonce"):
                connect_secure(
                    context(),
                    key=session_key(),
                    _socket_factory=socket_factory_for(fake),
                    _nonce_factory=lambda size: CLIENT_NONCE,
                )

        self.assertTrue(fake.closed)

    def test_expired_session_key_raises_before_socket_open(self):
        fake = FakeSocket()

        with self.assertRaises(ExpiredKeyError):
            connect_secure(
                context(),
                key=session_key(abs_validity=1000),
                _socket_factory=socket_factory_for(fake),
                _nonce_factory=lambda size: CLIENT_NONCE,
            )

        self.assertFalse(fake.closed)
        self.assertFalse(hasattr(fake, "opened_with"))

    def test_tcp_early_close_raises_auth_connection_error(self):
        fake = FakeSocket()

        with patch(
            "iotauth.secure_channel.build_handshake_1",
            return_value=b"handshake1",
        ):
            with self.assertRaises(AuthConnectionError):
                connect_secure(
                    context(),
                    key=session_key(),
                    _socket_factory=socket_factory_for(fake),
                    _nonce_factory=lambda size: CLIENT_NONCE,
                )

        self.assertTrue(fake.closed)

    def test_context_convenience_method_delegates_to_secure_channel(self):
        ctx = context()
        key = session_key()
        with patch("iotauth.secure_channel.connect_secure", return_value="channel") as conn:
            self.assertEqual(ctx.connect_secure(key=key, timeout=1.0), "channel")

        conn.assert_called_once_with(
            ctx,
            key=key,
            host=None,
            port=None,
            timeout=1.0,
        )

    def test_accept_secure_completes_server_handshake(self):
        key = session_key()
        fake = FakeSocket(
            frame(MessageType.SKEY_HANDSHAKE_1, b"12345678handshake1")
            + frame(MessageType.SKEY_HANDSHAKE_3, b"handshake3")
        )

        with patch(
            "iotauth.secure_channel.verify_handshake_1_and_build_handshake_2",
            return_value=(CLIENT_NONCE, b"handshake2"),
        ) as verify_h1, patch(
            "iotauth.secure_channel.verify_handshake_3",
            return_value=None,
        ) as verify_h3:
            channel = accept_secure(
                context_with_key(key),
                fake,
                _nonce_factory=lambda size: b"s" * 8,
            )

        self.assertIsInstance(channel, SecureChannel)
        self.assertIs(channel.socket, fake)
        self.assertIs(channel.session_key, key)
        verify_h1.assert_called_once_with(key, b"12345678handshake1", b"s" * 8)
        verify_h3.assert_called_once_with(key, b"handshake3", b"s" * 8)

        sent = parse_frame(fake.sent[0])
        self.assertEqual(sent, IoTSPFrame(MessageType.SKEY_HANDSHAKE_2, b"handshake2"))
        self.assertFalse(fake.closed)

    def test_accept_secure_unknown_session_key_raises_handshake_error(self):
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_1, b"87654321handshake1"))

        with self.assertRaisesRegex(SecureHandshakeError, "not found"):
            accept_secure(
                context(),
                fake,
                _nonce_factory=lambda size: b"s" * 8,
            )

        self.assertTrue(fake.closed)

    def test_accept_secure_wrong_first_frame_type_raises_handshake_error(self):
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_2, b"payload"))

        with self.assertRaisesRegex(SecureHandshakeError, "SKEY_HANDSHAKE_1"):
            accept_secure(
                context_with_key(session_key()),
                fake,
                _nonce_factory=lambda size: b"s" * 8,
            )

        self.assertTrue(fake.closed)

    def test_accept_secure_wrong_third_frame_type_raises_handshake_error(self):
        key = session_key()
        fake = FakeSocket(
            frame(MessageType.SKEY_HANDSHAKE_1, b"12345678handshake1")
            + frame(MessageType.AUTH_ALERT, b"\x01")
        )

        with patch(
            "iotauth.secure_channel.verify_handshake_1_and_build_handshake_2",
            return_value=(CLIENT_NONCE, b"handshake2"),
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "SKEY_HANDSHAKE_3"):
                accept_secure(
                    context_with_key(key),
                    fake,
                    _nonce_factory=lambda size: b"s" * 8,
                )

        self.assertTrue(fake.closed)

    def test_accept_secure_expired_session_key_raises(self):
        key = session_key(abs_validity=1000)
        fake = FakeSocket(frame(MessageType.SKEY_HANDSHAKE_1, b"12345678handshake1"))

        with self.assertRaises(ExpiredKeyError):
            accept_secure(
                context_with_key(key),
                fake,
                _nonce_factory=lambda size: b"s" * 8,
            )

        self.assertTrue(fake.closed)

    def test_accept_secure_tcp_early_close_raises_auth_connection_error(self):
        fake = FakeSocket()

        with self.assertRaises(AuthConnectionError):
            accept_secure(
                context_with_key(session_key()),
                fake,
                _nonce_factory=lambda size: b"s" * 8,
            )

        self.assertTrue(fake.closed)

    def test_accept_secure_context_convenience_method_delegates(self):
        ctx = context()
        fake = FakeSocket()
        with patch("iotauth.secure_channel.accept_secure", return_value="channel") as acc:
            self.assertEqual(ctx.accept_secure(fake, timeout=1.0), "channel")

        acc.assert_called_once_with(ctx, fake, timeout=1.0)

    def test_serializes_and_parses_secure_message_plaintext(self):
        plaintext = _serialize_secure_message(0, b"hello")

        self.assertEqual(plaintext[:8], b"\x00" * 8)
        self.assertEqual(_parse_secure_message(plaintext), (0, b"hello"))

    def test_rejects_short_secure_message_plaintext(self):
        with self.assertRaisesRegex(SerializationError, "sequence"):
            _parse_secure_message(b"short")

    def test_rejects_sequence_number_overflow(self):
        with self.assertRaises(InvalidSequenceNumberError):
            _serialize_secure_message(MAX_SEQUENCE_NUMBER + 1, b"payload")

    def test_send_writes_secure_comm_message_and_increments_sequence(self):
        key = session_key()
        fake = FakeSocket()
        channel = SecureChannel(fake, key)

        channel.send(b"hello")

        sent = parse_frame(fake.sent[0])
        self.assertEqual(sent.message_type, MessageType.SECURE_COMM_MSG)
        decrypted = symmetric_decrypt_authenticate(
            sent.payload,
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        self.assertEqual(_parse_secure_message(decrypted), (0, b"hello"))
        self.assertEqual(channel.send_sequence, 1)

    def test_failed_send_does_not_increment_sequence(self):
        channel = SecureChannel(FailingSendSocket(), session_key())

        with self.assertRaises(AuthConnectionError):
            channel.send(b"hello")

        self.assertEqual(channel.send_sequence, 0)

    def test_send_after_close_raises_channel_closed(self):
        channel = SecureChannel(FakeSocket(), session_key())
        channel.close()

        with self.assertRaises(SecureChannelClosed):
            channel.send(b"hello")

    def test_send_with_expired_key_raises(self):
        channel = SecureChannel(FakeSocket(), session_key(abs_validity=1000))

        with self.assertRaises(ExpiredKeyError):
            channel.send(b"hello")

    def test_recv_decrypts_secure_comm_message_and_increments_sequence(self):
        key = session_key()
        encrypted = symmetric_encrypt_authenticate(
            _serialize_secure_message(0, b"hello"),
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        channel = SecureChannel(
            FakeSocket(frame(MessageType.SECURE_COMM_MSG, encrypted)),
            key,
        )

        self.assertEqual(channel.recv(), b"hello")
        self.assertEqual(channel.receive_sequence, 1)

    def test_recv_rejects_wrong_message_type(self):
        channel = SecureChannel(FakeSocket(frame(MessageType.AUTH_ALERT, b"\x01")), session_key())

        with self.assertRaisesRegex(SerializationError, "SECURE_COMM_MSG"):
            channel.recv()

    def test_recv_rejects_sequence_mismatch(self):
        key = session_key()
        encrypted = symmetric_encrypt_authenticate(
            _serialize_secure_message(1, b"hello"),
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        channel = SecureChannel(
            FakeSocket(frame(MessageType.SECURE_COMM_MSG, encrypted)),
            key,
        )

        with self.assertRaises(InvalidSequenceNumberError):
            channel.recv()
        self.assertEqual(channel.receive_sequence, 0)

    def test_recv_rejects_tampered_payload(self):
        key = session_key()
        encrypted = symmetric_encrypt_authenticate(
            _serialize_secure_message(0, b"hello"),
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        channel = SecureChannel(
            FakeSocket(frame(MessageType.SECURE_COMM_MSG, tampered)),
            key,
        )

        with self.assertRaises(MessageIntegrityError):
            channel.recv()

    def test_recv_after_close_raises_channel_closed(self):
        channel = SecureChannel(FakeSocket(), session_key())
        channel.close()

        with self.assertRaises(SecureChannelClosed):
            channel.recv()

    def test_recv_with_expired_key_raises(self):
        key = session_key(abs_validity=1000)
        encrypted = symmetric_encrypt_authenticate(
            _serialize_secure_message(0, b"hello"),
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        channel = SecureChannel(
            FakeSocket(frame(MessageType.SECURE_COMM_MSG, encrypted)),
            key,
        )

        with self.assertRaises(ExpiredKeyError):
            channel.recv()

    def test_recv_translates_early_close_to_channel_closed(self):
        channel = SecureChannel(FakeSocket(), session_key())

        with self.assertRaises(SecureChannelClosed):
            channel.recv()
        self.assertTrue(channel.closed)

    def test_secure_channel_round_trip_updates_independent_counters(self):
        key = session_key()
        client_socket = FakeSocket()
        server_socket = FakeSocket()
        client = SecureChannel(client_socket, key)
        server = SecureChannel(server_socket, key)

        client.send(b"hello")
        server_socket.incoming.extend(client_socket.sent.pop(0))
        self.assertEqual(server.recv(), b"hello")

        server.send(b"ack")
        client_socket.incoming.extend(server_socket.sent.pop(0))
        self.assertEqual(client.recv(), b"ack")

        self.assertEqual(client.send_sequence, 1)
        self.assertEqual(client.receive_sequence, 1)
        self.assertEqual(server.send_sequence, 1)
        self.assertEqual(server.receive_sequence, 1)


if __name__ == "__main__":
    unittest.main()
