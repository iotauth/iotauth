"""Tests for the high-level SecureClient and SecureServer wrappers."""

import unittest

from iotauth import (
    AuthConnectionError,
    AuthInfo,
    EntityConfig,
    EntityInfo,
    IoTAuthContext,
    SecureChannelClosed,
    SecureClient,
    SecureServer,
    SessionConfig,
    SessionKeyCache,
    TargetServer,
)
from tests.helpers import FakeListenSocket, make_session_key


class FakeChannel:
    def __init__(self):
        self.sent = []
        self.to_receive = [b"reply"]
        self.closed = False

    def send(self, data):
        self.sent.append(data)

    def recv(self):
        return self.to_receive.pop(0)

    def close(self):
        self.closed = True


class FakeContext(IoTAuthContext):
    def __init__(self, as_server=False):
        super().__init__(
            config=EntityConfig(
                entity=EntityInfo(name="net1.test", private_key_path=None),
                auth=AuthInfo(
                    id=101,
                    host="127.0.0.1",
                    port=21900,
                    public_key_path=None,
                ),
                session=SessionConfig(
                    protocol="TCP",
                    encryption_mode="AES_128_CBC",
                    distribution_encryption_mode="AES_128_CBC",
                ),
                purposes=[{"group": "Clients"}] if as_server else [{"group": "Servers"}],
                num_keys=1,
                targets=[TargetServer(host="127.0.0.1", port=21100)],
            ),
            auth_public_key=None,
            entity_private_key=None,
            distribution_key=None,
            session_keys=SessionKeyCache(),
        )
        self.request_calls = []
        self.connect_calls = []
        self.accept_calls = []
        self.requested_key = make_session_key()
        self.channel = FakeChannel()

    def request_session_keys(self, **kwargs):
        self.request_calls.append(kwargs)
        return [self.requested_key]

    def connect_secure(self, **kwargs):
        self.connect_calls.append(kwargs)
        return self.channel

    def accept_secure(self, sock, *, timeout=5.0):
        self.accept_calls.append({"sock": sock, "timeout": timeout})
        return self.channel


class SecureClientTests(unittest.TestCase):
    """Tests for the SecureClient high-level API wrapper."""

    def test_connect_uses_provided_key_without_requesting(self):
        ctx = FakeContext()
        key = make_session_key()
        client = SecureClient(ctx, key=key, host="example.test", port=1234, timeout=1.5)

        channel = client.connect()

        self.assertIs(channel, ctx.channel)
        self.assertEqual(ctx.request_calls, [])
        self.assertEqual(
            ctx.connect_calls,
            [{"key": key, "host": "example.test", "port": 1234, "timeout": 1.5}],
        )

    def test_connect_requests_session_key_when_missing(self):
        ctx = FakeContext()
        client = SecureClient(ctx, purpose={"group": "Servers"}, timeout=2.0)

        client.connect()

        self.assertEqual(
            ctx.request_calls,
            [{"purpose": {"group": "Servers"}, "timeout": 2.0}],
        )
        self.assertEqual(ctx.connect_calls[0]["key"], ctx.requested_key)
        self.assertIs(client.key, ctx.requested_key)

    def test_send_and_recv_delegate_to_active_channel(self):
        ctx = FakeContext()
        client = SecureClient(ctx, key=make_session_key())
        client.connect()

        client.send(b"hello")
        reply = client.recv()

        self.assertEqual(ctx.channel.sent, [b"hello"])
        self.assertEqual(reply, b"reply")

    def test_send_before_connect_raises_channel_closed(self):
        client = SecureClient(FakeContext(), key=make_session_key())

        with self.assertRaises(SecureChannelClosed):
            client.send(b"hello")

    def test_close_closes_active_channel(self):
        ctx = FakeContext()
        client = SecureClient(ctx, key=make_session_key())
        client.connect()

        client.close()

        self.assertTrue(ctx.channel.closed)

    def test_context_manager_closes_on_exit(self):
        ctx = FakeContext()
        with SecureClient(ctx, key=make_session_key()) as client:
            client.connect()

        self.assertTrue(ctx.channel.closed)


class SecureServerTests(unittest.TestCase):
    """Tests for the SecureServer high-level API wrapper."""

    def test_listen_binds_and_listens_once(self):
        fake = FakeListenSocket()
        server = SecureServer(
            FakeContext(as_server=True), _socket_factory=lambda: fake, timeout=1.5
        )

        server.listen()
        server.listen()

        self.assertEqual(fake.bound, ("127.0.0.1", 21100))
        self.assertEqual(fake.listened, 5)
        self.assertEqual(fake.timeout, 1.5)

    def test_listen_allows_host_port_override(self):
        fake = FakeListenSocket()
        server = SecureServer(
            FakeContext(as_server=True),
            host="0.0.0.0",
            port=12345,
            backlog=9,
            _socket_factory=lambda: fake,
        )

        server.listen()

        self.assertEqual(fake.bound, ("0.0.0.0", 12345))
        self.assertEqual(fake.listened, 9)

    def test_serve_once_accepts_and_delegates_to_context(self):
        ctx = FakeContext(as_server=True)
        fake = FakeListenSocket()
        server = SecureServer(ctx, _socket_factory=lambda: fake, timeout=2.0)

        channel = server.serve_once()

        self.assertEqual(channel, ctx.channel)
        self.assertEqual(
            ctx.accept_calls,
            [{"sock": fake.accepted_socket, "timeout": 2.0}],
        )

    def test_close_closes_listening_socket(self):
        fake = FakeListenSocket()
        server = SecureServer(FakeContext(as_server=True), _socket_factory=lambda: fake)
        server.listen()

        server.close()

        self.assertTrue(fake.closed)
        self.assertIsNone(server._socket)

    def test_context_manager_closes_on_exit(self):
        fake = FakeListenSocket()
        with SecureServer(FakeContext(as_server=True), _socket_factory=lambda: fake) as server:
            server.listen()

        self.assertTrue(fake.closed)

    def test_bind_failure_raises_auth_connection_error(self):
        fake = FakeListenSocket(fail_bind=True)
        server = SecureServer(FakeContext(as_server=True), _socket_factory=lambda: fake)

        with self.assertRaises(AuthConnectionError):
            server.listen()

        self.assertTrue(fake.closed)

    def test_accept_failure_raises_auth_connection_error(self):
        fake = FakeListenSocket(fail_accept=True)
        server = SecureServer(FakeContext(as_server=True), _socket_factory=lambda: fake)

        with self.assertRaises(AuthConnectionError):
            server.serve_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
