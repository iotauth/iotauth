import unittest
from unittest.mock import patch

from iotauth import (
    HANDSHAKE_FIXED_SIZE,
    HANDSHAKE_NONCE_PRESENT,
    HANDSHAKE_REPLY_NONCE_PRESENT,
    HandshakePayload,
    MessageIntegrityError,
    SecureHandshakeError,
    SerializationError,
    SessionKey,
    build_handshake_1,
    parse_handshake_1_key_id,
    parse_handshake_payload,
    serialize_handshake_payload,
    symmetric_decrypt_authenticate,
    verify_handshake_1_and_build_handshake_2,
    verify_handshake_2_and_build_handshake_3,
    verify_handshake_3,
)
from iotauth.crypto import _load_crypto_backend


CLIENT_NONCE = b"c" * 8
SERVER_NONCE = b"s" * 8


def session_key():
    return SessionKey(
        id=b"12345678",
        cipher_key=b"k" * 16,
        mac_key=b"m" * 32,
        abs_validity=0xFFFFFFFFFFFF,
        rel_validity=60000,
        encryption_mode="AES_128_CBC",
        hmac_enabled=True,
        permanent_distribution_key=False,
    )


def has_cryptography():
    try:
        _load_crypto_backend()
        return True
    except Exception:
        return False


CRYPTOGRAPHY_AVAILABLE = has_cryptography()


class HandshakePayloadTests(unittest.TestCase):
    def test_serializes_nonce_only_payload(self):
        payload = serialize_handshake_payload(HandshakePayload(nonce=CLIENT_NONCE))

        self.assertEqual(payload[0], HANDSHAKE_NONCE_PRESENT)
        self.assertEqual(payload[1:9], CLIENT_NONCE)
        self.assertEqual(len(payload), HANDSHAKE_FIXED_SIZE)

    def test_serializes_reply_nonce_only_payload(self):
        payload = serialize_handshake_payload(
            HandshakePayload(reply_nonce=SERVER_NONCE)
        )

        self.assertEqual(payload[0], HANDSHAKE_REPLY_NONCE_PRESENT)
        self.assertEqual(payload[9:17], SERVER_NONCE)
        self.assertEqual(len(payload), HANDSHAKE_FIXED_SIZE)

    def test_serializes_nonce_plus_reply_nonce_payload(self):
        payload = serialize_handshake_payload(
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=CLIENT_NONCE)
        )

        self.assertEqual(payload[0], 0x03)
        self.assertEqual(payload[1:9], SERVER_NONCE)
        self.assertEqual(payload[9:17], CLIENT_NONCE)

    def test_rejects_payload_without_any_field(self):
        with self.assertRaisesRegex(SerializationError, "at least one"):
            serialize_handshake_payload(HandshakePayload())

    def test_parses_nonce_only_payload(self):
        parsed = parse_handshake_payload(bytes([0x01]) + CLIENT_NONCE)

        self.assertEqual(parsed, HandshakePayload(nonce=CLIENT_NONCE))

    def test_parses_nonce_plus_reply_nonce_payload(self):
        parsed = parse_handshake_payload(
            bytes([0x03]) + SERVER_NONCE + CLIENT_NONCE
        )

        self.assertEqual(
            parsed,
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=CLIENT_NONCE),
        )

    def test_rejects_truncated_nonce(self):
        with self.assertRaisesRegex(SerializationError, "nonce"):
            parse_handshake_payload(b"\x01abc")


class HandshakeBuilderTests(unittest.TestCase):
    def test_build_handshake_1_prefixes_session_key_id(self):
        with patch(
            "iotauth.handshake.symmetric_encrypt_authenticate",
            return_value=b"encrypted",
        ):
            payload = build_handshake_1(session_key(), CLIENT_NONCE)

        self.assertEqual(payload, b"12345678encrypted")

    def test_parse_handshake_1_key_id(self):
        self.assertEqual(parse_handshake_1_key_id(b"12345678encrypted"), b"12345678")

    def test_parse_handshake_1_key_id_rejects_short_payload(self):
        with self.assertRaisesRegex(SerializationError, "session key ID"):
            parse_handshake_1_key_id(b"short")

    def test_verify_handshake_1_builds_handshake_2(self):
        clear_handshake_1 = serialize_handshake_payload(
            HandshakePayload(nonce=CLIENT_NONCE)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_1,
        ), patch(
            "iotauth.handshake.symmetric_encrypt_authenticate",
            return_value=b"handshake2",
        ):
            client_nonce, handshake_2 = verify_handshake_1_and_build_handshake_2(
                session_key(),
                b"12345678encrypted-handshake1",
                SERVER_NONCE,
            )

        self.assertEqual(client_nonce, CLIENT_NONCE)
        self.assertEqual(handshake_2, b"handshake2")

    def test_verify_handshake_1_rejects_missing_client_nonce(self):
        clear_handshake_1 = serialize_handshake_payload(
            HandshakePayload(reply_nonce=SERVER_NONCE)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_1,
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "client nonce"):
                verify_handshake_1_and_build_handshake_2(
                    session_key(),
                    b"12345678encrypted-handshake1",
                    SERVER_NONCE,
                )

    def test_verify_handshake_2_builds_handshake_3(self):
        clear_handshake_2 = serialize_handshake_payload(
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=CLIENT_NONCE)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_2,
        ), patch(
            "iotauth.handshake.symmetric_encrypt_authenticate",
            return_value=b"handshake3",
        ):
            server_nonce, handshake_3 = verify_handshake_2_and_build_handshake_3(
                session_key(),
                b"encrypted-handshake2",
                CLIENT_NONCE,
            )

        self.assertEqual(server_nonce, SERVER_NONCE)
        self.assertEqual(handshake_3, b"handshake3")

    def test_verify_handshake_2_rejects_nonce_mismatch(self):
        clear_handshake_2 = serialize_handshake_payload(
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=b"x" * 8)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_2,
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "reply nonce"):
                verify_handshake_2_and_build_handshake_3(
                    session_key(),
                    b"encrypted-handshake2",
                    CLIENT_NONCE,
                )

    def test_verify_handshake_3_accepts_matching_reply_nonce(self):
        clear_handshake_3 = serialize_handshake_payload(
            HandshakePayload(reply_nonce=SERVER_NONCE)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_3,
        ):
            parsed = verify_handshake_3(
                session_key(),
                b"encrypted-handshake3",
                SERVER_NONCE,
            )

        self.assertEqual(parsed.reply_nonce, SERVER_NONCE)

    def test_verify_handshake_3_rejects_nonce_mismatch(self):
        clear_handshake_3 = serialize_handshake_payload(
            HandshakePayload(reply_nonce=b"x" * 8)
        )
        with patch(
            "iotauth.handshake.symmetric_decrypt_authenticate",
            return_value=clear_handshake_3,
        ):
            with self.assertRaisesRegex(SecureHandshakeError, "reply nonce"):
                verify_handshake_3(
                    session_key(),
                    b"encrypted-handshake3",
                    SERVER_NONCE,
                )


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography is not installed")
class HandshakeCryptoTests(unittest.TestCase):
    def test_build_handshake_1_decrypts_to_client_nonce(self):
        key = session_key()

        encrypted = build_handshake_1(key, CLIENT_NONCE)
        plaintext = symmetric_decrypt_authenticate(
            encrypted[8:],
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )

        self.assertEqual(
            parse_handshake_payload(plaintext),
            HandshakePayload(nonce=CLIENT_NONCE),
        )

    def test_server_and_client_handshake_helpers_round_trip(self):
        key = session_key()
        handshake_1 = build_handshake_1(key, CLIENT_NONCE)

        client_nonce, handshake_2 = verify_handshake_1_and_build_handshake_2(
            key,
            handshake_1,
            SERVER_NONCE,
        )
        server_nonce, handshake_3 = verify_handshake_2_and_build_handshake_3(
            key,
            handshake_2,
            CLIENT_NONCE,
        )
        parsed_handshake_3 = verify_handshake_3(key, handshake_3, SERVER_NONCE)

        self.assertEqual(client_nonce, CLIENT_NONCE)
        self.assertEqual(server_nonce, SERVER_NONCE)
        self.assertEqual(parsed_handshake_3.reply_nonce, SERVER_NONCE)

    def test_tampered_handshake_2_raises_integrity_error(self):
        key = session_key()
        clear_handshake_2 = serialize_handshake_payload(
            HandshakePayload(nonce=SERVER_NONCE, reply_nonce=CLIENT_NONCE)
        )
        from iotauth import symmetric_encrypt_authenticate

        encrypted = symmetric_encrypt_authenticate(
            clear_handshake_2,
            key.cipher_key,
            key.mac_key,
            key.encryption_mode,
            key.hmac_enabled,
        )
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])

        with self.assertRaises(MessageIntegrityError):
            verify_handshake_2_and_build_handshake_3(key, tampered, CLIENT_NONCE)


if __name__ == "__main__":
    unittest.main()
