import unittest

from iotauth import (
    AuthConnectionError,
    MessageIntegrityError,
    SecureChannel,
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


class TimingOutSocket(FakeSocket):
    def recv(self, size):
        raise TimeoutError("timed out")


def frame(message_type, payload):
    return serialize_frame(IoTSPFrame(message_type, payload))


class SecureChannelTests(unittest.TestCase):
    """Tests for the secure session channel and communication."""

    def test_recv_translates_timeout_and_restores_socket_state(self):
        fake = TimingOutSocket()
        fake.settimeout(9.0)
        channel = SecureChannel(fake, make_session_key())

        with self.assertRaisesRegex(AuthConnectionError, "timed out"):
            channel.recv(timeout=0.25)

        self.assertEqual(fake.gettimeout(), 9.0)

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
