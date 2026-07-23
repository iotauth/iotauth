import unittest

from iotauth import (
    AuthConnectionError,
    AuthInfo,
    EntityConfig,
    EntityInfo,
    IoTAuthContext,
    MessageIntegrityError,
    SecureChannel,
    SessionConfig,
    SessionKeyCache,
    TargetServer,
)
from iotauth.crypto import (
    _load_crypto_backend,
    symmetric_encrypt_authenticate,
)
from iotauth.protocol import IoTSPFrame, MessageType, serialize_frame
from iotauth.secure_channel import (
    _serialize_secure_message,
)
from tests.helpers import FakeSocket, make_session_key


def has_cryptography():
    try:
        _load_crypto_backend()
        return True
    except Exception:
        return False


CRYPTOGRAPHY_AVAILABLE = has_cryptography()


CLIENT_NONCE = b"c" * 8


class TimingOutSocket(FakeSocket):
    def recv(self, size):
        raise TimeoutError("timed out")


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
    """Tests for the secure session channel and communication."""

    def test_channel_state_is_encapsulated(self):
        channel = SecureChannel(FakeSocket(), make_session_key())

        self.assertFalse(channel.closed)
        self.assertFalse(hasattr(channel, "socket"))
        self.assertFalse(hasattr(channel, "session_key"))
        self.assertFalse(hasattr(channel, "send_sequence"))
        self.assertFalse(hasattr(channel, "receive_sequence"))
        with self.assertRaises(AttributeError):
            channel.closed = True

    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    def test_recv_translates_timeout_and_restores_socket_state(self):
        fake = TimingOutSocket()
        fake.settimeout(9.0)
        channel = SecureChannel(fake, make_session_key())

        with self.assertRaisesRegex(AuthConnectionError, "timed out"):
            channel.recv(timeout=0.25)

        self.assertEqual(fake.gettimeout(), 9.0)

    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    def test_recv_rejects_tampered_payload(self):
        key = make_session_key()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
