import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from iotauth import IoTAuthContext
from iotauth.config import _load_config


class IoTAuthContextTests(unittest.TestCase):
    """Tests for parsing configurations and initializing the runtime context."""

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
