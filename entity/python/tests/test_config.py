from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from iotauth import ConfigError, load_config


class LoadConfigTests(unittest.TestCase):
    def test_loads_c_style_config(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            auth_key = root / "auth.pem"
            entity_key = root / "entity.pem"
            auth_key.write_text("auth", encoding="utf-8")
            entity_key.write_text("entity", encoding="utf-8")
            config_path = root / "client.config"
            config_path.write_text(
                "\n".join(
                    [
                        "# comment",
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
                ),
                encoding="utf-8",
            )

            config = load_config(config_path)

            self.assertEqual(config.entity.name, "net1.client")
            self.assertEqual(config.auth.id, 101)
            self.assertEqual(config.auth.port, 21900)
            self.assertEqual(config.num_keys, 3)
            self.assertEqual(config.session.protocol, "TCP")
            self.assertEqual(config.session.encryption_mode, "AES_128_CBC")
            self.assertTrue(config.session.hmac_enabled)
            self.assertFalse(config.session.permanent_distribution_key)
            self.assertEqual(config.purposes, [{"group": "Servers"}])
            self.assertEqual(config.targets[0].host, "127.0.0.1")
            self.assertEqual(config.targets[0].port, 21100)
            self.assertEqual(config.auth.public_key_path, auth_key.resolve())
            self.assertEqual(config.entity.private_key_path, entity_key.resolve())

    def test_keeps_non_json_purpose_as_raw_string(self):
        config = self._load_minimal_config('entityInfo.purpose={"keyId":00000000}')

        self.assertEqual(config.purposes, ['{"keyId":00000000}'])

    def test_rejects_missing_required_key(self):
        with self.assertRaisesRegex(ConfigError, "Missing required config key"):
            self._load_minimal_config(skip={"authInfo.id"})

    def test_rejects_bad_integer(self):
        with self.assertRaisesRegex(ConfigError, "auth.port.number must be an integer"):
            self._load_minimal_config(override={"auth.port.number": "abc"})

    def test_rejects_unsupported_protocol(self):
        with self.assertRaisesRegex(ConfigError, "Unsupported network.protocol"):
            self._load_minimal_config(override={"network.protocol": "UDP"})

    def test_rejects_missing_key_file(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "client.config"
            config_path.write_text(
                self._minimal_config_text(
                    root,
                    override={
                        "authInfo.pubkey.path": "missing-auth.pem",
                        "entityInfo.privkey.path": "missing-entity.pem",
                    },
                    create_keys=False,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigError, "existing file"):
                load_config(config_path)

    def _load_minimal_config(self, purpose_line=None, override=None, skip=None):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "client.config"
            config_path.write_text(
                self._minimal_config_text(root, purpose_line, override, skip),
                encoding="utf-8",
            )
            return load_config(config_path)

    def _minimal_config_text(
        self,
        root,
        purpose_line=None,
        override=None,
        skip=None,
        create_keys=True,
    ):
        override = override or {}
        skip = skip or set()
        if create_keys:
            (root / "auth.pem").write_text("auth", encoding="utf-8")
            (root / "entity.pem").write_text("entity", encoding="utf-8")

        values = {
            "entityInfo.name": "net1.client",
            "entityInfo.number_key": "3",
            "authInfo.id": "101",
            "sessionKey.encryptionMode": "AES_128_CBC",
            "authInfo.pubkey.path": "auth.pem",
            "entityInfo.privkey.path": "entity.pem",
            "auth.ip.address": "127.0.0.1",
            "auth.port.number": "21900",
            "entity.server.ip.address": "127.0.0.1",
            "entity.server.port.number": "21100",
            "network.protocol": "TCP",
        }
        values.update(override)
        lines = []
        if purpose_line:
            lines.append(purpose_line)
        for key, value in values.items():
            if key not in skip:
                lines.append(f"{key}={value}")
        return "\n".join(lines)


if __name__ == "__main__":
    unittest.main()
