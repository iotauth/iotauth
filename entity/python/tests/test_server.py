import unittest

from iotauth import (
    AuthConnectionError,
    AuthInfo,
    EntityConfig,
    EntityInfo,
    IoTAuthContext,
    SecureServer,
    SessionConfig,
    SessionKeyCache,
    TargetServer,
)


class FakeListenSocket:
    def __init__(self, *, fail_bind=False, fail_accept=False):
        self.bound = None
        self.listened = None
        self.timeout = None
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


class TestContext(IoTAuthContext):
    def __init__(self):
        super().__init__(
            config=EntityConfig(
                entity=EntityInfo(name="net1.server", private_key_path=None),
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
                purposes=[{"group": "Clients"}],
                num_keys=1,
                targets=[TargetServer(host="127.0.0.1", port=21100)],
            ),
            auth_public_key=None,
            entity_private_key=None,
            distribution_key=None,
            session_keys=SessionKeyCache(),
        )
        self.accept_calls = []

    def accept_secure(self, sock, *, timeout=5.0):
        self.accept_calls.append({"sock": sock, "timeout": timeout})
        return "channel"


class SecureServerTests(unittest.TestCase):
    def test_listen_binds_and_listens_once(self):
        fake = FakeListenSocket()
        server = SecureServer(TestContext(), _socket_factory=lambda: fake, timeout=1.5)

        server.listen()
        server.listen()

        self.assertEqual(fake.bound, ("127.0.0.1", 21100))
        self.assertEqual(fake.listened, 5)
        self.assertEqual(fake.timeout, 1.5)

    def test_listen_allows_host_port_override(self):
        fake = FakeListenSocket()
        server = SecureServer(
            TestContext(),
            host="0.0.0.0",
            port=12345,
            backlog=9,
            _socket_factory=lambda: fake,
        )

        server.listen()

        self.assertEqual(fake.bound, ("0.0.0.0", 12345))
        self.assertEqual(fake.listened, 9)

    def test_serve_once_accepts_and_delegates_to_context(self):
        ctx = TestContext()
        fake = FakeListenSocket()
        server = SecureServer(ctx, _socket_factory=lambda: fake, timeout=2.0)

        channel = server.serve_once()

        self.assertEqual(channel, "channel")
        self.assertEqual(
            ctx.accept_calls,
            [{"sock": fake.accepted_socket, "timeout": 2.0}],
        )

    def test_close_closes_listening_socket(self):
        fake = FakeListenSocket()
        server = SecureServer(TestContext(), _socket_factory=lambda: fake)
        server.listen()

        server.close()

        self.assertTrue(fake.closed)
        self.assertIsNone(server._socket)

    def test_context_manager_closes_on_exit(self):
        fake = FakeListenSocket()
        with SecureServer(TestContext(), _socket_factory=lambda: fake) as server:
            server.listen()

        self.assertTrue(fake.closed)

    def test_bind_failure_raises_auth_connection_error(self):
        fake = FakeListenSocket(fail_bind=True)
        server = SecureServer(TestContext(), _socket_factory=lambda: fake)

        with self.assertRaises(AuthConnectionError):
            server.listen()

        self.assertTrue(fake.closed)

    def test_accept_failure_raises_auth_connection_error(self):
        fake = FakeListenSocket(fail_accept=True)
        server = SecureServer(TestContext(), _socket_factory=lambda: fake)

        with self.assertRaises(AuthConnectionError):
            server.serve_once()


if __name__ == "__main__":
    unittest.main()
