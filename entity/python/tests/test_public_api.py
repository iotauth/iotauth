"""Tests for the intentionally small package-level API."""

import unittest

import iotauth

EXPECTED_PUBLIC_API = {
    "AuthConnectionError",
    "AuthInfo",
    "AuthProtocolError",
    "ConfigError",
    "CredentialError",
    "DistributionKey",
    "EntityConfig",
    "EntityInfo",
    "ExpiredKeyError",
    "InvalidSequenceNumberError",
    "IoTAuthContext",
    "IoTAuthError",
    "KeyCacheError",
    "load_config",
    "MessageIntegrityError",
    "SecureChannel",
    "SecureChannelClosed",
    "SecureClient",
    "SecureClientStateError",
    "SecureHandshakeError",
    "SecureServer",
    "SerializationError",
    "SessionConfig",
    "SessionKey",
    "SessionKeyCache",
    "TargetServer",
    "UnsupportedCryptoError",
}


class PublicApiTests(unittest.TestCase):
    def test_top_level_exports_only_supported_user_api(self):
        self.assertEqual(set(iotauth.__all__), EXPECTED_PUBLIC_API)
        for name in EXPECTED_PUBLIC_API:
            with self.subTest(name=name):
                self.assertTrue(hasattr(iotauth, name))

    def test_low_level_helpers_are_not_top_level_exports(self):
        low_level_names = {
            "build_handshake_1",
            "connect_secure",
            "encode_varint",
            "parse_frame",
            "public_encrypt",
            "recv_frame",
            "request_session_keys",
            "serialize_frame",
            "symmetric_encrypt_authenticate",
        }

        self.assertTrue(low_level_names.isdisjoint(iotauth.__all__))
        for name in low_level_names:
            with self.subTest(name=name):
                self.assertFalse(hasattr(iotauth, name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
