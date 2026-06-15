import unittest
from unittest.mock import patch

from iotauth import (
    AuthConnectionError,
    AuthInfo,
    EntityConfig,
    EntityInfo,
    ExpiredKeyError,
    IoTAuthContext,
    IoTSPFrame,
    MessageType,
    SecureChannel,
    SecureHandshakeError,
    SessionConfig,
    SessionKey,
    SessionKeyCache,
    TargetServer,
    connect_secure,
    parse_frame,
    serialize_frame,
    session_key_is_expired,
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


if __name__ == "__main__":
    unittest.main()
