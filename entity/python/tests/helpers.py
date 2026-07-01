"""Shared test helpers for the IoTAuth Python API test suite."""

from iotauth import SessionKey


class FakeSocket:
    def __init__(self, incoming=b"", eof_on_empty=False):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.closed = False
        self.timeout = None
        self.eof_on_empty = eof_on_empty

    def recv(self, size):
        if self.closed or (not self.incoming and self.eof_on_empty):
            return b""
        if not self.incoming:
            raise BlockingIOError()
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, data):
        if self.closed:
            raise OSError("Socket is closed")
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


class FakeListenSocket:
    def __init__(self, *, fail_bind=False, fail_accept=False):
        self.bound = None
        self.listened = None
        self.timeout = None
        self.sockopt = None
        self.closed = False
        self.fail_bind = fail_bind
        self.fail_accept = fail_accept
        self.accepted_socket = object()

    def settimeout(self, timeout):
        self.timeout = timeout

    def setsockopt(self, *args):
        self.sockopt = args

    def bind(self, address):
        if self.fail_bind:
            raise OSError("bind failed")
        self.bound = address

    def listen(self, backlog):
        self.listened = backlog

    def accept(self):
        if self.fail_accept:
            raise OSError("accept failed")
        return self.accepted_socket, ("127.0.0.1", 12345)

    def close(self):
        self.closed = True


def make_session_key(
    key_id=b"12345678",
    cipher_key=b"c" * 16,
    mac_key=b"m" * 32,
    abs_validity=0xFFFFFFFFFFFF,
    rel_validity=60000,
    encryption_mode="AES_128_CBC",
    hmac_enabled=True,
    permanent_distribution_key=False,
) -> SessionKey:
    """Helper to create a SessionKey with default fake values for testing."""
    return SessionKey(
        id=key_id,
        cipher_key=cipher_key,
        mac_key=mac_key,
        abs_validity=abs_validity,
        rel_validity=rel_validity,
        encryption_mode=encryption_mode,
        hmac_enabled=hmac_enabled,
        permanent_distribution_key=permanent_distribution_key,
    )
