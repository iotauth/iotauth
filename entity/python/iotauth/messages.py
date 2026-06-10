"""IoTAuth message types and frame objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .exceptions import SerializationError


class MessageType(IntEnum):
    AUTH_HELLO = 0
    ENTITY_HELLO = 1
    AUTH_SESSION_KEY_REQ = 10
    AUTH_SESSION_KEY_RESP = 11
    SESSION_KEY_REQ_IN_PUB_ENC = 20
    SESSION_KEY_RESP_WITH_DIST_KEY = 21
    SESSION_KEY_REQ = 22
    SESSION_KEY_RESP = 23
    SESSION_KEY_RESP_FOR_DELEGATION = 24
    SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY = 25
    SKEY_HANDSHAKE_1 = 30
    SKEY_HANDSHAKE_2 = 31
    SKEY_HANDSHAKE_3 = 32
    SECURE_COMM_MSG = 33
    FIN_SECURE_COMM = 34
    SECURE_PUB = 40
    MIGRATION_REQ_WITH_SIGN = 50
    MIGRATION_RESP_WITH_SIGN = 51
    MIGRATION_REQ_WITH_MAC = 52
    MIGRATION_RESP_WITH_MAC = 53
    ADD_READER_REQ_IN_PUB_ENC = 60
    ADD_READER_RESP_WITH_DIST_KEY = 61
    ADD_READER_REQ = 62
    ADD_READER_RESP = 63
    DELEGATED_ACCESS_REQ_IN_PUB_ENC = 70
    DELEGATED_ACCESS_RESP_WITH_DIST_KEY = 71
    DELEGATED_ACCESS_REQ = 72
    DELEGATED_ACCESS_RESP = 73
    PRIVILEGED_REQ_IN_PUB_ENC = 80
    PRIVILEGED_RESP_WITH_DIST_KEY = 81
    PRIVILEGED_REQ = 82
    PRIVILEGED_RESP = 83
    AUTH_ALERT = 100


@dataclass(frozen=True)
class IoTSPFrame:
    message_type: MessageType
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, MessageType):
            object.__setattr__(
                self, "message_type", message_type_from_byte(int(self.message_type))
            )
        if not isinstance(self.payload, bytes):
            raise SerializationError("IoTSPFrame payload must be bytes")


def message_type_from_byte(value: int) -> MessageType:
    try:
        return MessageType(value)
    except ValueError as exc:
        raise SerializationError(f"Unknown IoTAuth message type: {value}") from exc
