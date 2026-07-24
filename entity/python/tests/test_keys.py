import unittest

from iotauth import DistributionKey, SessionKeyCache
from tests.helpers import make_session_key


class SessionKeyCacheTests(unittest.TestCase):
    """Tests for the session key cache data structure."""

    def test_adds_and_retrieves_key_by_id(self):
        cache = SessionKeyCache()
        key = make_session_key()

        cache.add(key)

        self.assertEqual(len(cache), 1)
        self.assertIs(cache.get(b"12345678"), key)
        self.assertIs(cache.require(b"12345678"), key)


class KeyRepresentationTests(unittest.TestCase):
    """Tests that object representations do not expose secret key bytes."""

    def test_session_key_repr_redacts_key_material(self):
        key = make_session_key(
            cipher_key=b"session-key-1234",
            mac_key=b"session-mac-secret-1234567890123",
        )

        representation = repr(key)

        self.assertNotIn("session-key-1234", representation)
        self.assertNotIn("session-mac-secret-1234567890123", representation)
        self.assertNotIn("cipher_key", representation)
        self.assertNotIn("mac_key", representation)
        self.assertIn("id=b'12345678'", representation)
        self.assertIn("encryption_mode='AES_128_CBC'", representation)

    def test_distribution_key_repr_redacts_key_material(self):
        key = DistributionKey(
            cipher_key=b"dist-cipher-key!",
            mac_key=b"distribution-mac-secret-12345678",
            abs_validity=123456,
            encryption_mode="AES_128_CBC",
        )

        representation = repr(key)

        self.assertNotIn("dist-cipher-key!", representation)
        self.assertNotIn("distribution-mac-secret-12345678", representation)
        self.assertNotIn("cipher_key", representation)
        self.assertNotIn("mac_key", representation)
        self.assertIn("abs_validity=123456", representation)
        self.assertIn("encryption_mode='AES_128_CBC'", representation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
