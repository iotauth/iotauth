import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from iotauth import CredentialError, IoTAuthContext
from iotauth.config import _load_config
from iotauth.credentials import load_entity_private_key


class CredentialLoadingTests(unittest.TestCase):
    """Tests for loading entity private keys and Auth public certificates."""

    def test_missing_cryptography_dependency_is_clear(self):
        with TemporaryDirectory() as temp_dir:
            key_path = Path(temp_dir) / "entity.pem"
            key_path.write_text("not a real key", encoding="utf-8")

            with patch.dict(
                "sys.modules",
                {
                    "cryptography": None,
                    "cryptography.hazmat": None,
                    "cryptography.hazmat.primitives": None,
                    "cryptography.hazmat.primitives.serialization": None,
                },
            ):
                with self.assertRaisesRegex(CredentialError, "cryptography package"):
                    load_entity_private_key(key_path)


class IoTAuthContextTests(unittest.TestCase):
    """Tests for parsing configurations and initializing the runtime context."""

    def test_internal_context_initialization_loads_credentials_and_empty_cache(self):
        with TemporaryDirectory() as temp_dir:
            config = self._load_config(Path(temp_dir))

            with (
                patch("iotauth.context.load_auth_public_key", return_value="auth-key") as load_auth,
                patch(
                    "iotauth.context.load_entity_private_key",
                    return_value="entity-key",
                ) as load_entity,
            ):
                ctx = IoTAuthContext._from_entity_config(config)

            self.assertIs(ctx.config, config)
            self.assertEqual(ctx.auth_public_key, "auth-key")
            self.assertEqual(ctx.entity_private_key, "entity-key")
            self.assertIsNone(ctx.distribution_key)
            self.assertEqual(len(ctx.session_keys), 0)
            representation = repr(ctx)
            self.assertNotIn("entity-key", representation)
            self.assertNotIn("entity_private_key", representation)
            self.assertNotIn(", distribution_key=", representation)
            self.assertNotIn("session_keys", representation)
            self.assertIn("auth-key", representation)
            load_auth.assert_called_once_with(config.auth.public_key_path)
            load_entity.assert_called_once_with(config.entity.private_key_path)

    def test_from_config_loads_config_then_credentials(self):
        with TemporaryDirectory() as temp_dir:
            config_path = self._write_config(Path(temp_dir))

            with (
                patch("iotauth.context.load_auth_public_key", return_value="auth-key"),
                patch("iotauth.context.load_entity_private_key", return_value="entity-key"),
            ):
                ctx = IoTAuthContext.from_config(config_path)

            self.assertEqual(ctx.config.entity.name, "net1.client")
            self.assertEqual(ctx.auth_public_key, "auth-key")

    def test_permanent_distribution_key_mode_loads_key(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "dist.cipher").write_bytes(b"0123456789abcdef")
            (root / "dist.mac").write_bytes(b"mac-secret-key-0123456789abcdef")
            config = self._load_config(
                root,
                extra_lines=[
                    "PermanentDistKeyMode=on",
                    "distKey.cipherkey.path=dist.cipher",
                    "distkey.mackey.path=dist.mac",
                    "distKey.validity=365*day",
                ],
                omit_rsa_credentials=True,
            )

            ctx = IoTAuthContext._from_entity_config(config)
            self.assertIsNotNone(ctx.distribution_key)
            self.assertEqual(ctx.distribution_key.cipher_key, b"0123456789abcdef")
            self.assertEqual(ctx.distribution_key.mac_key, b"mac-secret-key-0123456789abcdef")
            self.assertIsNotNone(ctx.distribution_key.abs_validity)
            self.assertIsNone(ctx.auth_public_key)
            self.assertIsNone(ctx.entity_private_key)
            representation = repr(ctx)
            self.assertNotIn("0123456789abcdef", representation)
            self.assertNotIn("mac-secret-key-0123456789abcdef", representation)

    def _load_config(self, root, extra_lines=None, omit_rsa_credentials=False):
        return _load_config(self._write_config(root, extra_lines, omit_rsa_credentials))

    def _write_config(self, root, extra_lines=None, omit_rsa_credentials=False):
        (root / "auth.pem").write_text("auth", encoding="utf-8")
        (root / "entity.pem").write_text("entity", encoding="utf-8")
        config_path = root / "client.config"
        lines = [
            "entityInfo.name=net1.client",
            'entityInfo.purpose={"group":"Servers"}',
            "entityInfo.number_key=3",
            "authInfo.id=101",
            "sessionKey.encryptionMode=AES_128_CBC",
            "authInfo.pubkey.path=auth.pem",
            "entityInfo.privkey.path=entity.pem",
            "auth.ip.address=127.0.0.1",
            "auth.port.number=21900",
            "entity.server.ip.address=127.0.0.1",
            "entity.server.port.number=21100",
            "network.protocol=TCP",
        ]
        if omit_rsa_credentials:
            lines.remove("authInfo.pubkey.path=auth.pem")
            lines.remove("entityInfo.privkey.path=entity.pem")
        lines.extend(extra_lines or [])
        config_path.write_text("\n".join(lines), encoding="utf-8")
        return config_path


if __name__ == "__main__":
    unittest.main(verbosity=2)
