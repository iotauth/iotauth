import unittest

from iotauth import DistributionKey, KeyCacheError, SessionKeyCache
from tests.helpers import make_session_key


class SessionKeyCacheTests(unittest.TestCase):
    """Tests for the session key cache data structure."""

    def test_cache_starts_empty(self):
        cache = SessionKeyCache()

        self.assertEqual(len(cache), 0)

    def test_adds_and_retrieves_key_by_id(self):
        cache = SessionKeyCache()
        key = make_session_key()

        cache.add(key)

        self.assertEqual(len(cache), 1)
        self.assertIs(cache.get(b"12345678"), key)
        self.assertIs(cache.require(b"12345678"), key)

    def test_rejects_invalid_key_id_size(self):
        with self.assertRaisesRegex(KeyCacheError, "8 bytes"):
            make_session_key(b"short")

    def test_rejects_duplicate_key_without_replace(self):
        cache = SessionKeyCache()
        cache.add(make_session_key())

        with self.assertRaisesRegex(KeyCacheError, "already exists"):
            cache.add(make_session_key())

    def test_replace_allows_existing_key_update(self):
        cache = SessionKeyCache()
        old_key = make_session_key()
        new_key = make_session_key()
        cache.add(old_key)

        cache.add(new_key, replace=True)

        self.assertIs(cache.require(b"12345678"), new_key)

    def test_allows_unbounded_key_count(self):
        cache = SessionKeyCache()
        for i in range(20):
            cache.add(make_session_key(f"{i:08d}".encode("ascii")))

        self.assertEqual(len(cache), 20)


class KeyRepresentationTests(unittest.TestCase):
    """Tests that object representations do not expose secret key bytes."""

    def test_session_key_repr_redacts_key_material(self):
        key = make_session_key(
            cipher_key=b"session-cipher-secret",
            mac_key=b"session-mac-secret",
        )

        representation = repr(key)

        self.assertNotIn("session-cipher-secret", representation)
        self.assertNotIn("session-mac-secret", representation)
        self.assertNotIn("cipher_key", representation)
        self.assertNotIn("mac_key", representation)
        self.assertIn("id=b'12345678'", representation)
        self.assertIn("encryption_mode='AES_128_CBC'", representation)

    def test_distribution_key_repr_redacts_key_material(self):
        key = DistributionKey(
            cipher_key=b"distribution-cipher-secret",
            mac_key=b"distribution-mac-secret",
            abs_validity=123456,
            encryption_mode="AES_128_CBC",
        )

        representation = repr(key)

        self.assertNotIn("distribution-cipher-secret", representation)
        self.assertNotIn("distribution-mac-secret", representation)
        self.assertNotIn("cipher_key", representation)
        self.assertNotIn("mac_key", representation)
        self.assertIn("abs_validity=123456", representation)
        self.assertIn("encryption_mode='AES_128_CBC'", representation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
