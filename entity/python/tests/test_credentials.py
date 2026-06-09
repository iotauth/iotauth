from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from iotauth import CredentialError
from iotauth.credentials import load_entity_private_key


class CredentialLoadingTests(unittest.TestCase):
    def test_missing_cryptography_dependency_is_clear(self):
        with TemporaryDirectory() as temp_dir:
            key_path = Path(temp_dir) / "entity.pem"
            key_path.write_text("not a real key", encoding="utf-8")

            with patch("builtins.__import__", side_effect=ImportError("missing")):
                with self.assertRaisesRegex(CredentialError, "cryptography package"):
                    load_entity_private_key(key_path)


if __name__ == "__main__":
    unittest.main()
