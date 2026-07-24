# Python Tests

This directory contains a focused set of tests for behavior that is not fully asserted by the Python client-server integration tests.

Run the tests from `entity/python`:

```bash
python -m unittest discover -s tests -v
```

## `test_auth_service.py`

- `test_public_key_request_mode_sends_public_key_encrypted_message` verifies that an entity without a distribution key sends the public-key-protected session-key request type.
- `test_session_key_response_adds_keys_to_cache` verifies that session keys returned by Auth are stored in the context cache.
- `test_response_with_distribution_key_updates_context` verifies that a distribution key returned by Auth is saved for future requests.
- `test_permanent_distribution_key_missing_or_expired_raises` verifies that permanent-key mode rejects missing or expired distribution keys with `CredentialError`.

## `test_config.py`

- `test_loads_c_style_config` verifies that the Python API continues to parse the supported C-style properties configuration format.
- `test_loads_properties_permanent_distribution_key` verifies that permanent distribution-key paths and validity are parsed from a properties configuration.

## `test_context.py`

- `test_permanent_distribution_key_mode_loads_key` verifies that permanent distribution-key files are loaded without requiring RSA credentials and that their secrets are not exposed by the context representation.

## `test_crypto.py`

- `test_hmac_detects_tampering` verifies that authenticated symmetric decryption rejects a modified ciphertext.
- `test_signature_verification_detects_tampering` verifies that RSA signature validation rejects modified data.
- `test_encrypt_and_sign_envelope_round_trip` verifies that an Auth request envelope can be encrypted, signed, verified, and decrypted correctly.

## `test_handshake.py`

- `test_tampered_handshake_2_raises_integrity_error` verifies that the client rejects a modified second handshake message.

## `test_keys.py`

- `test_adds_and_retrieves_key_by_id` verifies basic session-key cache insertion and lookup.
- `test_session_key_repr_redacts_key_material` verifies that `SessionKey` representations do not reveal cipher or MAC keys.
- `test_distribution_key_repr_redacts_key_material` verifies that `DistributionKey` representations do not reveal cipher or MAC keys.

## `test_secure_channel.py`

- `test_channel_state_is_encapsulated` verifies that socket and sequence state remain private implementation details.
- `test_recv_translates_timeout_and_restores_socket_state` verifies that receive timeouts become `AuthConnectionError` and that the previous socket timeout is restored.
- `test_recv_rejects_tampered_payload` verifies that a secure channel rejects modified encrypted messages.
