import unittest

from iotauth import SecureChannelClosed, SecureClient, SessionKey


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


class FakeContext:
    def __init__(self):
        self.request_calls = []
        self.connect_calls = []
        self.requested_key = session_key()
        self.channel = FakeChannel()

    def request_session_keys(self, **kwargs):
        self.request_calls.append(kwargs)
        return [self.requested_key]

    def connect_secure(self, **kwargs):
        self.connect_calls.append(kwargs)
        return self.channel


class SecureClientTests(unittest.TestCase):
    def test_connect_uses_provided_key_without_requesting(self):
        ctx = FakeContext()
        key = session_key()
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
        client = SecureClient(ctx, key=session_key())
        client.connect()

        client.send(b"hello")
        reply = client.recv()

        self.assertEqual(ctx.channel.sent, [b"hello"])
        self.assertEqual(reply, b"reply")

    def test_send_before_connect_raises_channel_closed(self):
        client = SecureClient(FakeContext(), key=session_key())

        with self.assertRaises(SecureChannelClosed):
            client.send(b"hello")

    def test_close_closes_active_channel(self):
        ctx = FakeContext()
        client = SecureClient(ctx, key=session_key())
        client.connect()

        client.close()

        self.assertTrue(ctx.channel.closed)

    def test_context_manager_closes_on_exit(self):
        ctx = FakeContext()
        with SecureClient(ctx, key=session_key()) as client:
            client.connect()

        self.assertTrue(ctx.channel.closed)


if __name__ == "__main__":
    unittest.main()
