import unittest

from iotauth import KeyCacheError, SessionKey, SessionKeyCache


from tests.helpers import make_session_key

class SessionKeyCacheTests(unittest.TestCase):
    """Tests for the session key cache data structure."""

    def test_cache_starts_empty(self):
        cache = SessionKeyCache()

        self.assertEqual(len(cache), 0)
        self.assertTrue(cache.has_room())

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

    def test_enforces_max_key_count(self):
        cache = SessionKeyCache(max_keys=1)
        cache.add(make_session_key())

        with self.assertRaisesRegex(KeyCacheError, "full"):
            cache.add(make_session_key(b"87654321"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
