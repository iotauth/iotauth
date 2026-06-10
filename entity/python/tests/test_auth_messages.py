import unittest

from iotauth import (
    NONCE_SIZE,
    AuthAlertPayload,
    AuthHelloPayload,
    DistributionKey,
    SerializationError,
    SessionConfig,
    SessionKey,
    SessionKeyRequestPayload,
    decode_uint_be,
    encode_uint_be,
    parse_auth_alert_payload,
    parse_auth_hello_payload,
    parse_buffered_string,
    parse_distribution_key_record,
    parse_session_key_record,
    parse_session_key_response_payload,
    serialize_buffered_string,
    serialize_session_key_request_payload,
)


def session_config(hmac_enabled=True):
    return SessionConfig(
        protocol="TCP",
        encryption_mode="AES_128_CBC",
        distribution_encryption_mode="AES_128_CBC",
        hmac_enabled=hmac_enabled,
        permanent_distribution_key=False,
    )


def session_key_record(
    key_id=b"12345678",
    abs_validity=0x010203040506,
    rel_validity=0x010203040507,
    cipher_key=b"c" * 16,
    mac_key=b"m" * 32,
):
    return (
        key_id
        + encode_uint_be(abs_validity, 6)
        + encode_uint_be(rel_validity, 6)
        + bytes([len(cipher_key)])
        + cipher_key
        + bytes([len(mac_key)])
        + mac_key
    )


class AuthPayloadTests(unittest.TestCase):
    def test_parses_auth_hello_payload(self):
        payload = encode_uint_be(101, 4) + b"a" * NONCE_SIZE

        parsed = parse_auth_hello_payload(payload)

        self.assertEqual(parsed, AuthHelloPayload(auth_id=101, nonce=b"a" * 8))

    def test_rejects_invalid_auth_hello_length(self):
        with self.assertRaisesRegex(SerializationError, "AUTH_HELLO"):
            parse_auth_hello_payload(b"short")

    def test_parses_auth_alert_payload(self):
        self.assertEqual(parse_auth_alert_payload(b"\x01"), AuthAlertPayload(code=1))

    def test_rejects_invalid_auth_alert_length(self):
        with self.assertRaisesRegex(SerializationError, "AUTH_ALERT"):
            parse_auth_alert_payload(b"\x01\x02")


class BufferedStringTests(unittest.TestCase):
    def test_round_trips_utf8_buffered_string(self):
        encoded = serialize_buffered_string("net1.client-µ")

        value, consumed = parse_buffered_string(encoded)

        self.assertEqual(value, "net1.client-µ")
        self.assertEqual(consumed, len(encoded))

    def test_rejects_truncated_buffered_string(self):
        with self.assertRaisesRegex(SerializationError, "exceeds"):
            parse_buffered_string(b"\x05abc")


class SessionKeyRequestTests(unittest.TestCase):
    def test_serializes_session_key_request_with_dict_purpose(self):
        request = SessionKeyRequestPayload(
            entity_nonce=b"e" * 8,
            auth_nonce=b"a" * 8,
            num_keys=3,
            entity_name="net1.client",
            purpose={"group": "Servers"},
        )

        payload = serialize_session_key_request_payload(request)
        offset = 0

        self.assertEqual(payload[offset : offset + 8], b"e" * 8)
        offset += 8
        self.assertEqual(payload[offset : offset + 8], b"a" * 8)
        offset += 8
        self.assertEqual(decode_uint_be(payload[offset : offset + 4]), 3)
        offset += 4
        entity_name, consumed = parse_buffered_string(payload, offset)
        self.assertEqual(entity_name, "net1.client")
        offset += consumed
        purpose, consumed = parse_buffered_string(payload, offset)
        self.assertEqual(purpose, '{"group":"Servers"}')
        offset += consumed
        self.assertEqual(offset, len(payload))

    def test_preserves_raw_purpose_string(self):
        request = SessionKeyRequestPayload(
            entity_nonce=b"e" * 8,
            auth_nonce=b"a" * 8,
            num_keys=1,
            entity_name="net1.server",
            purpose='{"keyId":00000000}',
        )

        payload = serialize_session_key_request_payload(request)
        _, consumed = parse_buffered_string(payload, 20)
        purpose, _ = parse_buffered_string(payload, 20 + consumed)

        self.assertEqual(purpose, '{"keyId":00000000}')

    def test_rejects_invalid_nonce_length(self):
        request = SessionKeyRequestPayload(
            entity_nonce=b"short",
            auth_nonce=b"a" * 8,
            num_keys=1,
            entity_name="net1.client",
            purpose={"group": "Servers"},
        )

        with self.assertRaisesRegex(SerializationError, "entity_nonce"):
            serialize_session_key_request_payload(request)


class KeyRecordTests(unittest.TestCase):
    def test_parses_distribution_key_record(self):
        record = (
            encode_uint_be(0x010203040506, 6)
            + b"\x10"
            + b"c" * 16
            + b"\x20"
            + b"m" * 32
        )

        key = parse_distribution_key_record(record)

        self.assertEqual(
            key,
            DistributionKey(
                cipher_key=b"c" * 16,
                mac_key=b"m" * 32,
                abs_validity=0x010203040506,
                encryption_mode="AES_128_CBC",
            ),
        )

    def test_parses_session_key_record(self):
        record = session_key_record()

        key, consumed = parse_session_key_record(record, 0, session_config())

        self.assertEqual(consumed, len(record))
        self.assertEqual(
            key,
            SessionKey(
                id=b"12345678",
                cipher_key=b"c" * 16,
                mac_key=b"m" * 32,
                abs_validity=0x010203040506,
                rel_validity=0x010203040507,
                encryption_mode="AES_128_CBC",
                hmac_enabled=True,
                permanent_distribution_key=False,
            ),
        )

    def test_rejects_truncated_session_key_record(self):
        with self.assertRaisesRegex(SerializationError, "fixed fields"):
            parse_session_key_record(b"short", 0, session_config())


class SessionKeyResponseTests(unittest.TestCase):
    def test_parses_cleartext_session_key_response(self):
        key_record = session_key_record()
        payload = (
            b"e" * 8
            + serialize_buffered_string('{"cipher":"AES-128-CBC","mac":"SHA256"}')
            + encode_uint_be(1, 4)
            + key_record
        )

        response = parse_session_key_response_payload(payload, session_config())

        self.assertEqual(response.entity_nonce, b"e" * 8)
        self.assertEqual(
            response.crypto_spec, {"cipher": "AES-128-CBC", "mac": "SHA256"}
        )
        self.assertEqual(len(response.session_keys), 1)
        self.assertEqual(response.session_keys[0].id, b"12345678")

    def test_rejects_session_key_response_count_mismatch(self):
        payload = b"e" * 8 + serialize_buffered_string("{}") + encode_uint_be(1, 4)

        with self.assertRaisesRegex(SerializationError, "fixed fields"):
            parse_session_key_response_payload(payload, session_config())

    def test_rejects_trailing_session_key_response_bytes(self):
        payload = b"e" * 8 + serialize_buffered_string("{}") + encode_uint_be(0, 4) + b"x"

        with self.assertRaisesRegex(SerializationError, "trailing"):
            parse_session_key_response_payload(payload, session_config())


if __name__ == "__main__":
    unittest.main()
