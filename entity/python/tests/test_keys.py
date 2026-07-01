import unittest

from iotauth import KeyCacheError, SessionKeyCache
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
