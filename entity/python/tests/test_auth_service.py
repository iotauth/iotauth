import unittest
from unittest.mock import patch

from iotauth import (
    AuthInfo,
    AuthProtocolError,
    CredentialError,
    DistributionKey,
    EntityConfig,
    EntityInfo,
    IoTAuthContext,
    SessionConfig,
    SessionKeyCache,
    TargetServer,
)
from iotauth.auth_service import (
    request_session_keys,
)
from iotauth.protocol import (
    IoTSPFrame,
    MessageType,
    parse_frame,
    serialize_buffered_string,
    serialize_frame,
)
from iotauth.serialization import encode_uint_be
from tests.helpers import FakeSocket

ENTITY_NONCE = b"e" * 8
AUTH_NONCE = b"a" * 8


class FakeKey:
    key_size = 2048


def config(purposes=None, permanent_distribution_key=False):
    return EntityConfig(
        entity=EntityInfo(name="net1.client", private_key_path=None),
        auth=AuthInfo(id=101, host="127.0.0.1", port=21900, public_key_path=None),
        session=SessionConfig(
            protocol="TCP",
            encryption_mode="AES_128_CBC",
            distribution_encryption_mode="AES_128_CBC",
            permanent_distribution_key=permanent_distribution_key,
        ),
        purposes=[{"group": "Servers"}] if purposes is None else purposes,
        num_keys=1,
        targets=[TargetServer(host="127.0.0.1", port=21100)],
    )


def context(distribution_key=None, purposes=None, permanent_distribution_key=False):
    return IoTAuthContext(
        config=config(purposes=purposes, permanent_distribution_key=permanent_distribution_key),
        auth_public_key=FakeKey(),
        entity_private_key=FakeKey(),
        distribution_key=distribution_key,
        session_keys=SessionKeyCache(),
    )


def frame(message_type, payload):
    return serialize_frame(IoTSPFrame(message_type, payload))


def auth_hello(auth_id=101):
    return frame(MessageType.AUTH_HELLO, encode_uint_be(auth_id, 4) + AUTH_NONCE)


def session_key_record(key_id=b"12345678"):
    return (
        key_id
        + encode_uint_be(0xFFFFFFFFFFFF, 6)
        + encode_uint_be(60000, 6)
        + b"\x10"
        + b"c" * 16
        + b"\x20"
        + b"m" * 32
    )


def session_key_response_payload(entity_nonce=ENTITY_NONCE):
    return (
        entity_nonce + serialize_buffered_string("{}") + encode_uint_be(1, 4) + session_key_record()
    )


def distribution_key_record():
    return encode_uint_be(0xFFFFFFFFFFFF, 6) + b"\x10" + b"d" * 16 + b"\x20" + b"n" * 32


def socket_factory_for(fake_socket):
    def factory(host, port, timeout):
        return fake_socket

    return factory


class AuthServiceTests(unittest.TestCase):
    """Tests for the auth service protocol and session key negotiation."""

    def test_public_key_request_mode_sends_public_key_encrypted_message(self):
        fake = FakeSocket(auth_hello() + frame(MessageType.AUTH_ALERT, b"\x01"))

        with patch(
            "iotauth.auth_service.encrypt_and_sign_for_auth",
            return_value=b"public-protected",
        ):
            with self.assertRaisesRegex(AuthProtocolError, "invalid session key"):
                request_session_keys(
                    context(),
                    _socket_factory=socket_factory_for(fake),
                    _nonce_factory=lambda size: ENTITY_NONCE,
                )

        sent = parse_frame(fake.sent[0])
        self.assertEqual(sent.message_type, MessageType.SESSION_KEY_REQ_IN_PUB_ENC)
        self.assertEqual(sent.payload, b"public-protected")

    def test_session_key_response_adds_keys_to_cache(self):
        key = DistributionKey(
            cipher_key=b"c" * 16,
            mac_key=b"m" * 32,
            abs_validity=0xFFFFFFFFFFFF,
            encryption_mode="AES_128_CBC",
        )
        ctx = context(distribution_key=key)
        fake = FakeSocket(auth_hello() + frame(MessageType.SESSION_KEY_RESP, b"enc"))

        with (
            patch(
                "iotauth.auth_service.encrypt_request_with_distribution_key",
                return_value=b"dist-protected",
            ),
            patch(
                "iotauth.auth_service.symmetric_decrypt_authenticate",
                return_value=session_key_response_payload(),
            ),
        ):
            keys = request_session_keys(
                ctx,
                _socket_factory=socket_factory_for(fake),
                _nonce_factory=lambda size: ENTITY_NONCE,
            )

        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].id, b"12345678")
        self.assertIs(ctx.session_keys.require(b"12345678"), keys[0])

    def test_response_with_distribution_key_updates_context(self):
        ctx = context()
        response_payload = b"x" * 512 + b"encrypted-session-response"
        fake = FakeSocket(
            auth_hello() + frame(MessageType.SESSION_KEY_RESP_WITH_DIST_KEY, response_payload)
        )

        with (
            patch(
                "iotauth.auth_service.encrypt_and_sign_for_auth",
                return_value=b"public-protected",
            ),
            patch(
                "iotauth.auth_service.verify_and_decrypt_from_auth",
                return_value=distribution_key_record(),
            ),
            patch(
                "iotauth.auth_service.symmetric_decrypt_authenticate",
                return_value=session_key_response_payload(),
            ),
        ):
            keys = request_session_keys(
                ctx,
                _socket_factory=socket_factory_for(fake),
                _nonce_factory=lambda size: ENTITY_NONCE,
            )

        self.assertEqual(len(keys), 1)
        self.assertIsNotNone(ctx.distribution_key)
        self.assertEqual(ctx.distribution_key.cipher_key, b"d" * 16)
        self.assertEqual(ctx.session_keys.require(b"12345678").id, b"12345678")

    def test_missing_or_expired_permanent_distribution_key_raises_credential_error(self):
        from iotauth.auth_service import _protect_session_key_request

        ctx = context(permanent_distribution_key=True)
        with self.assertRaisesRegex(
            CredentialError, "Permanent distribution key is expired or missing"
        ):
            _protect_session_key_request(ctx, b"payload")

        ctx_expired = context(
            permanent_distribution_key=True,
            distribution_key=DistributionKey(
                cipher_key=b"c" * 16,
                mac_key=b"m" * 32,
                abs_validity=10,
                encryption_mode="AES_128_CBC",
            ),
        )
        with self.assertRaisesRegex(
            CredentialError, "Permanent distribution key is expired or missing"
        ):
            _protect_session_key_request(ctx_expired, b"payload")


if __name__ == "__main__":
    unittest.main(verbosity=2)
