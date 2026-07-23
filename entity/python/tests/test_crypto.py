import unittest

from iotauth import (
    IoTAuthContext,
    MessageIntegrityError,
    UnsupportedCryptoError,
)
from iotauth.config import AuthInfo, EntityConfig, EntityInfo, SessionConfig, TargetServer
from iotauth.crypto import (
    _load_crypto_backend,
    encrypt_and_sign_for_auth,
    sign_sha256,
    symmetric_decrypt_authenticate,
    symmetric_encrypt_authenticate,
    verify_and_decrypt_from_auth,
    verify_sha256,
)


def has_cryptography():
    try:
        _load_crypto_backend()
        return True
    except UnsupportedCryptoError:
        return False


CRYPTOGRAPHY_AVAILABLE = has_cryptography()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
class SymmetricCryptoTests(unittest.TestCase):
    """Tests for AES symmetric encryption and HMAC authentication."""

    def test_hmac_detects_tampering(self):
        envelope = symmetric_encrypt_authenticate(
            b"payload", b"c" * 16, b"m" * 32, "AES_128_CBC", True
        )
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])

        with self.assertRaises(MessageIntegrityError):
            symmetric_decrypt_authenticate(tampered, b"c" * 16, b"m" * 32, "AES_128_CBC", True)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
class PublicKeyCryptoTests(unittest.TestCase):
    """Tests for RSA public key encryption and signing."""

    def setUp(self):
        crypto = _load_crypto_backend()
        self.private_key = crypto["rsa"].generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def test_signature_verification_detects_tampering(self):
        signature = sign_sha256(b"payload", self.private_key)
        verify_sha256(b"payload", signature, self.public_key)

        with self.assertRaises(MessageIntegrityError):
            verify_sha256(b"tampered", signature, self.public_key)

    def test_encrypt_and_sign_envelope_round_trip(self):
        config = EntityConfig(
            entity=EntityInfo(name="net1.client", private_key_path=None),
            auth=AuthInfo(id=101, host="127.0.0.1", port=21900, public_key_path=None),
            session=SessionConfig(
                protocol="TCP",
                encryption_mode="AES_128_CBC",
                distribution_encryption_mode="AES_128_CBC",
            ),
            purposes=[],
            num_keys=1,
            targets=[TargetServer(host="127.0.0.1", port=21100)],
        )
        ctx = IoTAuthContext(
            config=config,
            auth_public_key=self.public_key,
            entity_private_key=self.private_key,
            distribution_key=None,
            session_keys=None,
        )

        envelope = encrypt_and_sign_for_auth(b"payload", ctx)

        self.assertEqual(
            verify_and_decrypt_from_auth(envelope, ctx, self.private_key.key_size // 8),
            b"payload",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
