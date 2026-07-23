import unittest

from iotauth import MessageIntegrityError
from iotauth.crypto import (
    _load_crypto_backend,
    symmetric_encrypt_authenticate,
)
from iotauth.handshake import (
    HandshakePayload,
    serialize_handshake_payload,
    verify_handshake_2_and_build_handshake_3,
)
from tests.helpers import make_session_key

CLIENT_NONCE = b"c" * 8
SERVER_NONCE = b"s" * 8


def has_cryptography():
    try:
        _load_crypto_backend()
        return True
    except Exception:
        return False


CRYPTOGRAPHY_AVAILABLE = has_cryptography()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
class HandshakeCryptoTests(unittest.TestCase):
    """Tests for handshake cryptography operations."""

    def test_tampered_handshake_2_raises_integrity_error(self):
        key = make_session_key()
        clear_handshake_2 = serialize_handshake_payload(
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=CLIENT_NONCE)
        )
        encrypted = symmetric_encrypt_authenticate(
            clear_handshake_2,
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])

        with self.assertRaises(MessageIntegrityError):
            verify_handshake_2_and_build_handshake_3(key, tampered, CLIENT_NONCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
