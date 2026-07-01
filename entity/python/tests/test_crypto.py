import unittest
from unittest.mock import patch

from iotauth import (
    DistributionKey,
    IoTAuthContext,
    MessageIntegrityError,
    SerializationError,
    UnsupportedCryptoError,
    decrypt_request_with_distribution_key,
    encrypt_request_with_distribution_key,
    symmetric_decrypt_authenticate,
    symmetric_encrypt_authenticate,
)
from iotauth.config import AuthInfo, EntityConfig, EntityInfo, SessionConfig, TargetServer
from iotauth.crypto import _load_crypto_backend


def has_cryptography():
    try:
        _load_crypto_backend()
        return True
    except UnsupportedCryptoError:
        return False


CRYPTOGRAPHY_AVAILABLE = has_cryptography()


class CryptoDependencyTests(unittest.TestCase):
    """Tests for cryptography package dependency injection."""

    def test_missing_cryptography_dependency_is_clear(self):
        with patch.dict(
            "sys.modules",
            {
                "cryptography": None,
                "cryptography.hazmat": None,
                "cryptography.hazmat.primitives": None,
                "cryptography.hazmat.primitives.serialization": None,
            },
        ):
            with self.assertRaisesRegex(UnsupportedCryptoError, "cryptography"):
                _load_crypto_backend()


class DistributionKeyWrapperTests(unittest.TestCase):
    """Tests for distribution key payload packaging."""

    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
    def test_distribution_key_wrapper_preserves_sender_name(self):
        key = DistributionKey(
            cipher_key=b"c" * 16,
            mac_key=b"m" * 32,
            abs_validity=None,
            encryption_mode="AES_128_CBC",
        )

        protected = encrypt_request_with_distribution_key(b"payload", "net1.client", key)
        sender, plaintext = decrypt_request_with_distribution_key(protected, key)

        self.assertEqual(protected[0], len("net1.client"))
        self.assertEqual(sender, "net1.client")
        self.assertEqual(plaintext, b"payload")

    def test_sender_name_must_fit_one_byte(self):
        key = DistributionKey(
            cipher_key=b"c" * 16,
            mac_key=b"m" * 32,
            abs_validity=None,
            encryption_mode="AES_128_CBC",
        )

        with self.assertRaisesRegex(SerializationError, "one byte"):
            encrypt_request_with_distribution_key(b"payload", "x" * 256, key)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
class SymmetricCryptoTests(unittest.TestCase):
    """Tests for AES symmetric encryption and HMAC authentication."""

    def test_aes_cbc_round_trip_with_hmac(self):
        self._round_trip("AES_128_CBC", hmac_enabled=True)

    def test_aes_ctr_round_trip_with_hmac(self):
        self._round_trip("AES_128_CTR", hmac_enabled=True)

    def test_aes_gcm_round_trip_without_hmac(self):
        self._round_trip("AES_128_GCM", hmac_enabled=False)

    def test_hmac_detects_tampering(self):
        envelope = symmetric_encrypt_authenticate(
            b"payload", b"c" * 16, b"m" * 32, "AES_128_CBC", True
        )
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])

        with self.assertRaises(MessageIntegrityError):
            symmetric_decrypt_authenticate(tampered, b"c" * 16, b"m" * 32, "AES_128_CBC", True)

    def test_rejects_wrong_aes_key_length(self):
        with self.assertRaisesRegex(UnsupportedCryptoError, "AES-128"):
            symmetric_encrypt_authenticate(b"payload", b"short", b"m" * 32, "AES_128_CBC", True)

    def test_rejects_unsupported_encryption_mode(self):
        with self.assertRaisesRegex(UnsupportedCryptoError, "Unsupported"):
            symmetric_encrypt_authenticate(b"payload", b"c" * 16, b"m" * 32, "AES_999", True)

    def _round_trip(self, mode, hmac_enabled):
        envelope = symmetric_encrypt_authenticate(
            b"payload", b"c" * 16, b"m" * 32, mode, hmac_enabled
        )
        plaintext = symmetric_decrypt_authenticate(
            envelope, b"c" * 16, b"m" * 32, mode, hmac_enabled
        )
        self.assertEqual(plaintext, b"payload")


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

    def test_public_encrypt_private_decrypt_round_trip(self):
        from iotauth import private_decrypt, public_encrypt

        ciphertext = public_encrypt(b"payload", self.public_key)

        self.assertEqual(private_decrypt(ciphertext, self.private_key), b"payload")

    def test_signature_verification_detects_tampering(self):
        from iotauth import sign_sha256, verify_sha256

        signature = sign_sha256(b"payload", self.private_key)
        verify_sha256(b"payload", signature, self.public_key)

        with self.assertRaises(MessageIntegrityError):
            verify_sha256(b"tampered", signature, self.public_key)

    def test_encrypt_and_sign_envelope_round_trip(self):
        from iotauth import encrypt_and_sign_for_auth, verify_and_decrypt_from_auth

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
