# Copyright 2024 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the opt-in ``strict_starttls`` mode.

These tests drive the server over loopback raw sockets (plus a temporary
trustme certificate) so that the exact byte sequence *received by the server*
is under our control, including pipelined plaintext and interrupted
handshakes that :mod:`smtplib` cannot produce.

Success is judged by what the handler records (AUTH / envelope / message
events), never by log lines such as "TLS started".
"""

import asyncio
import base64
import socket
import ssl
import struct
import sys
import time
from contextlib import suppress
from typing import Generator, List, Optional

import pytest

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import MISSING, AuthResult, Envelope, Session, SMTP
from aiosmtpd.testing.helpers import ReceivingHandler, catchup_delay

from .conftest import Global


# region #### Helpers #################################################################


class RecordingHandler(ReceivingHandler):
    """Records every hook the SMTP class might invoke, in receive order."""

    def __init__(self) -> None:
        super().__init__()
        self.auth_events: List[List[str]] = []
        self.mail_events: List[str] = []
        self.rcpt_events: List[str] = []
        self.data_events: List[Envelope] = []

    async def handle_AUTH(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        args: List[str],
    ):
        # Record what the server was asked to authenticate, then let the
        # built-in mechanisms + authenticator do the actual verification.
        self.auth_events.append(list(args))
        return MISSING

    async def handle_MAIL(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: List[str],
    ):
        self.mail_events.append(address)
        return MISSING

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: List[str],
    ):
        self.rcpt_events.append(address)
        return MISSING

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        # Keep our own record in addition to the inherited ``box``.
        self.data_events.append(envelope)
        return await super().handle_DATA(server, session, envelope)


def _authenticator(server, session, envelope, mechanism, auth_data) -> AuthResult:
    # Accept everything; the point is observing *whether* AUTH ran, not
    # credential verification.
    return AuthResult(success=True, handled=True, auth_data=auth_data)


def _raw_connect(controller: Controller) -> socket.socket:
    sock = socket.create_connection(
        (controller.hostname, controller.port), timeout=5.0
    )
    sock.settimeout(2.0)
    return sock


def _read_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def _read_reply(sock: socket.socket) -> bytes:
    """Read one (possibly multiline) SMTP reply; b"" means the peer closed."""
    lines: List[bytes] = []
    while True:
        line = _read_line(sock)
        if not line:
            break
        lines.append(line)
        # Fourth byte is a space on the final line of an SMTP reply.
        if len(line) >= 4 and line[3:4] == b" ":
            break
    return b"".join(lines)


def _drain(sock: socket.socket, overall_timeout: float = 3.0) -> bytes:
    """Read everything until the peer closes or briefly goes quiet."""
    deadline = time.monotonic() + overall_timeout
    chunks: List[bytes] = []
    sock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _close_tls(tls_sock: Optional[ssl.SSLSocket]) -> None:
    # Closing the SSLSocket itself (not just the raw socket) performs the
    # SSL shutdown and avoids "exception ignored while finalizing socket"
    # warnings on Windows when the object is garbage collected.
    if tls_sock is not None:
        with suppress(OSError):
            tls_sock.close()


def _wait_server_closed(controller: Controller, timeout: float = 5.0) -> bool:
    """Poll the (cross-thread) server until it drops the connection."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if controller.smtpd is not None and controller.smtpd.transport is None:
            return True
        catchup_delay(0.05)
    return False


def _assert_handler_got_nothing(handler: RecordingHandler) -> None:
    assert handler.auth_events == []
    assert handler.mail_events == []
    assert handler.rcpt_events == []
    assert handler.data_events == []
    assert handler.box == []


def _assert_no_delivery(handler: RecordingHandler) -> None:
    # MAIL/RCPT hooks may legitimately have run pre-TLS; what must never
    # happen is an actual DATA delivery of an unfinished transaction.
    assert handler.data_events == []
    assert handler.box == []


# endregion


# region #### Fixtures ###############################################################


def _make_controller(
    get_controller,
    handler: RecordingHandler,
    ssl_context_server: ssl.SSLContext,
    *,
    strict_starttls: bool,
) -> Controller:
    controller = get_controller(
        handler,
        decode_data=True,
        tls_context=ssl_context_server,
        strict_starttls=strict_starttls,
        authenticator=_authenticator,
    )
    controller.start()
    Global.set_addr_from(controller)
    return controller


@pytest.fixture
def strict_handler() -> RecordingHandler:
    return RecordingHandler()


@pytest.fixture
def strict_controller(
    get_controller, strict_handler, ssl_context_server
) -> Generator[Controller, None, None]:
    controller = _make_controller(
        get_controller,
        strict_handler,
        ssl_context_server,
        strict_starttls=True,
    )
    yield controller
    with suppress(AssertionError):
        controller.stop()


@pytest.fixture
def compat_controller(
    get_controller, strict_handler, ssl_context_server
) -> Generator[Controller, None, None]:
    controller = _make_controller(
        get_controller,
        strict_handler,
        ssl_context_server,
        strict_starttls=False,
    )
    yield controller
    with suppress(AssertionError):
        controller.stop()


# endregion


class TestStrictStartTLS:
    def test_option_passthrough_and_attribute(
        self, get_controller, strict_handler, ssl_context_server
    ):
        # The Controller must forward the keyword straight into SMTP_kwargs.
        controller = get_controller(
            strict_handler,
            tls_context=ssl_context_server,
            strict_starttls=True,
        )
        try:
            assert controller.SMTP_kwargs["strict_starttls"] is True
            controller.start()
            assert controller.smtpd.strict_starttls is True
        finally:
            with suppress(AssertionError):
                controller.stop()

    def test_pipelined_plaintext_is_dropped(
        self, strict_controller, strict_handler
    ):
        # The classic SMTP-smuggling shape: STARTTLS and the following
        # envelope commands are pushed in one segment, so MAIL/RCPT are
        # already buffered when the server parses STARTTLS.
        sock = _raw_connect(strict_controller)
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(
                b"STARTTLS\r\n"
                b"MAIL FROM:<anne@example.com>\r\n"
                b"RCPT TO:<bart@example.com>\r\n"
            )
            # No 220, no SMTP reply at all: the connection is torn down.
            assert _drain(sock) == b""
        finally:
            sock.close()

        assert _wait_server_closed(strict_controller)
        _assert_handler_got_nothing(strict_handler)
        # The buffered bytes must not have survived anywhere reachable.
        assert strict_controller.smtpd.envelope.mail_from is None
        assert strict_controller.smtpd.envelope.rcpt_tos == []

    def test_plaintext_segments_after_220_cannot_complete_handshake(
        self, strict_controller, strict_handler, ssl_context_client
    ):
        # Well-behaved up to the 220, then the client leaks plaintext in
        # several segments instead of a ClientHello.
        sock = _raw_connect(strict_controller)
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"

            # Two separate segments of plaintext, with a sync point between
            # them so the server has time to touch each one.
            sock.sendall(b"MAIL FROM:<anne@example.com>\r\n")
            catchup_delay()
            sock.sendall(b"RCPT TO:<bart@example.com>\r\n")
            catchup_delay()

            # Trying to continue the TLS handshake now must fail; the server
            # has treated the plaintext as malformed TLS records and aborted.
            with pytest.raises((ssl.SSLError, OSError)):
                ssl_context_client.wrap_socket(
                    sock, server_hostname="localhost"
                )
        finally:
            with suppress(OSError):
                sock.close()

        assert _wait_server_closed(strict_controller)
        _assert_handler_got_nothing(strict_handler)

    def test_normal_handshake_resets_all_state(
        self, strict_controller, strict_handler, ssl_context_client
    ):
        sock = _raw_connect(strict_controller)
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            assert _read_reply(sock).startswith(b"220")
            # Pre-TLS EHLO plus a half-open transaction that must be voided.
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"MAIL FROM:<old@example.com>\r\n")
            assert _read_reply(sock).startswith(b"250")
            assert strict_controller.smtpd.envelope.mail_from == "old@example.com"

            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"

            tls_sock = ssl_context_client.wrap_socket(
                sock, server_hostname="localhost"
            )
            # Sync point: handshake is done, server has run connection_made().
            catchup_delay()
            smtpd = strict_controller.smtpd
            # RFC 3207 §4.2: EHLO, AUTH state and transaction all forgotten.
            assert smtpd.session.host_name is None
            assert smtpd.session.authenticated is None
            assert smtpd.session.ssl is not None
            assert smtpd.envelope.mail_from is None
            assert smtpd.envelope.rcpt_tos == []

            # The pre-TLS transaction was never delivered (no DATA ran).
            assert strict_handler.box == []

            # Clean shutdown inside TLS.
            tls_sock.sendall(b"QUIT\r\n")
            assert _read_reply(tls_sock).startswith(b"221")
        finally:
            _close_tls(tls_sock)
            with suppress(OSError):
                sock.close()

        # No message delivery happened on this connection.
        _assert_no_delivery(strict_handler)

    def test_full_post_tls_transaction(
        self, strict_controller, strict_handler, ssl_context_client
    ):
        sock = _raw_connect(strict_controller)
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"

            tls_sock = ssl_context_client.wrap_socket(
                sock, server_hostname="localhost"
            )
            catchup_delay()

            # Client must re-EHLO inside TLS before anything else.
            tls_sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(tls_sock).startswith(b"250")

            credentials = base64.b64encode(b"\x00anne\x00s3cret-pw")
            tls_sock.sendall(b"AUTH PLAIN " + credentials + b"\r\n")
            assert _read_reply(tls_sock).startswith(b"235")

            tls_sock.sendall(b"MAIL FROM:<anne@example.com>\r\n")
            assert _read_reply(tls_sock).startswith(b"250")
            tls_sock.sendall(b"RCPT TO:<bart@example.com>\r\n")
            assert _read_reply(tls_sock).startswith(b"250")
            tls_sock.sendall(b"DATA\r\n")
            assert _read_reply(tls_sock).startswith(b"354")
            tls_sock.sendall(b"Subject: test\r\n\r\nbody\r\n.\r\n")
            assert _read_reply(tls_sock).startswith(b"250")

            tls_sock.sendall(b"QUIT\r\n")
            assert _read_reply(tls_sock).startswith(b"221")
        finally:
            _close_tls(tls_sock)
            with suppress(OSError):
                sock.close()

        # Exactly one of each, all from the post-TLS transaction.
        assert len(strict_handler.auth_events) == 1
        assert strict_handler.mail_events == ["anne@example.com"]
        assert strict_handler.rcpt_events == ["bart@example.com"]
        assert len(strict_handler.data_events) == 1
        assert len(strict_handler.box) == 1
        assert strict_handler.box[0].mail_from == "anne@example.com"
        assert strict_handler.box[0].rcpt_tos == ["bart@example.com"]
        assert "body" in strict_handler.box[0].content

    def test_smtplib_normal_client_works(
        self, strict_controller, strict_handler, client, ssl_context_client
    ):
        # A well-behaved high-level client that waits for 220 before the
        # handshake must work exactly as before, with re-EHLO after TLS.
        code, _ = client.ehlo("example.com")
        assert code == 250
        code, _ = client.starttls(context=ssl_context_client)
        assert code == 220
        code, _ = client.ehlo("example.com")
        assert code == 250
        client.sendmail(
            "anne@example.com", ["bart@example.com"], "hello\r\n"
        )
        client.quit()

        assert len(strict_handler.box) == 1
        assert strict_handler.box[0].mail_from == "anne@example.com"
        assert strict_handler.box[0].rcpt_tos == ["bart@example.com"]

    def test_commands_without_re_ehlo_after_tls_are_rejected(
        self, strict_controller, strict_handler, ssl_context_client
    ):
        sock = _raw_connect(strict_controller)
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"
            tls_sock = ssl_context_client.wrap_socket(
                sock, server_hostname="localhost"
            )
            catchup_delay()

            # No re-EHLO: envelope commands and AUTH must all be refused.
            tls_sock.sendall(b"MAIL FROM:<anne@example.com>\r\n")
            assert _read_reply(tls_sock).startswith(b"503")
            tls_sock.sendall(b"RCPT TO:<bart@example.com>\r\n")
            assert _read_reply(tls_sock).startswith(b"503")
            tls_sock.sendall(b"AUTH PLAIN AHRlc3QAdGVzdA==\r\n")
            assert _read_reply(tls_sock).startswith(b"503")
            tls_sock.sendall(b"DATA\r\n")
            assert _read_reply(tls_sock).startswith(b"503")

            tls_sock.sendall(b"QUIT\r\n")
            assert _read_reply(tls_sock).startswith(b"221")
        finally:
            _close_tls(tls_sock)
            with suppress(OSError):
                sock.close()

        _assert_handler_got_nothing(strict_handler)

    def test_garbage_instead_of_clienthello_aborts(
        self, strict_controller, strict_handler
    ):
        # Handshake *failure*: bytes that cannot be a TLS record.
        sock = _raw_connect(strict_controller)
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"
            sock.sendall(b"THIS IS NOT A TLS HANDSHAKE\r\n")
            # Server must close rather than keep a plaintext command channel.
            assert _drain(sock) == b""
        finally:
            sock.close()

        assert _wait_server_closed(strict_controller)
        _assert_handler_got_nothing(strict_handler)

    def test_handshake_abandoned_aborts(
        self, strict_controller, strict_handler
    ):
        # Handshake *cancellation*: client says STARTTLS then vanishes
        # without ever sending a ClientHello.
        sock = _raw_connect(strict_controller)
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(b"STARTTLS\r\n")
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"
            # Hard reset (SO_LINGER 0), no TLS bytes and no further commands.
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0),
            )
        finally:
            sock.close()

        assert _wait_server_closed(strict_controller)
        _assert_handler_got_nothing(strict_handler)

    def test_password_never_logged(
        self, strict_controller, strict_handler, caplog
    ):
        secret = "s3cret-pw-value"
        # Capture every level: the protocol readline logging runs at
        # INFO/DEBUG in addition to the strict-mode WARNING lines.
        caplog.set_level("DEBUG")
        sock = _raw_connect(strict_controller)
        try:
            _read_reply(sock)
            sock.sendall(b"EHLO example.com\r\n")
            _read_reply(sock)
            # A pipelined AUTH carrying the password in the clear: this
            # connection gets dropped by strict mode.
            blob = base64.b64encode(b"\x00anne\x00" + secret.encode())
            sock.sendall(b"STARTTLS\r\nAUTH PLAIN " + blob + b"\r\n")
            _drain(sock)
        finally:
            sock.close()

        assert _wait_server_closed(strict_controller)
        assert secret not in caplog.text
        assert blob.decode() not in caplog.text


class TestCompatMode:
    def test_legacy_behavior_without_strict_flag(
        self, compat_controller, strict_handler, ssl_context_client
    ):
        # With the option off, pipelining plaintext after STARTTLS must keep
        # the old, lenient behavior: the 220 is still sent, a proper TLS
        # handshake still works, and the stray bytes are silently discarded.
        sock = _raw_connect(compat_controller)
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            assert _read_reply(sock).startswith(b"220")
            sock.sendall(b"EHLO example.com\r\n")
            assert _read_reply(sock).startswith(b"250")
            sock.sendall(
                b"STARTTLS\r\n"
                b"MAIL FROM:<anne@example.com>\r\n"
                b"RCPT TO:<bart@example.com>\r\n"
            )
            # Legacy mode still answers 220 and the connection survives.
            assert _read_reply(sock) == b"220 Ready to start TLS\r\n"

            tls_sock = ssl_context_client.wrap_socket(
                sock, server_hostname="localhost"
            )
            catchup_delay()
            # The pipelined (pre-TLS) transaction was discarded, not delivered.
            tls_sock.sendall(b"MAIL FROM:<anne@example.com>\r\n")
            assert _read_reply(tls_sock).startswith(b"503")
            tls_sock.sendall(b"QUIT\r\n")
            assert _read_reply(tls_sock).startswith(b"221")
        finally:
            _close_tls(tls_sock)
            with suppress(OSError):
                sock.close()

        _assert_handler_got_nothing(strict_handler)


class TestStrictStartTLSUnit:
    """Deterministic, transport-mock level checks of the handshake boundary."""

    def test_connection_made_aborts_on_buffered_plaintext(
        self, temp_event_loop, mocker, ssl_context_server
    ):
        # Covers the narrow race where plaintext reaches the reader *after*
        # the STARTTLS pre-check but before the SSL layer's handshake
        # completion calls connection_made() again. A real failed handshake
        # never reaches this callback, so drive it with a mock transport.
        handler = RecordingHandler()
        proto = SMTP(
            handler,
            loop=temp_event_loop,
            tls_context=ssl_context_server,
            strict_starttls=True,
        )
        orig_transport = mocker.Mock()
        orig_transport.get_extra_info.return_value = ("127.0.0.1", 12345)
        proto.connection_made(orig_transport)
        handler_task = proto._handler_coroutine
        assert handler_task is not None

        # Plaintext commands already sitting in the reader's buffer.
        proto.data_received(b"STARTTLS\r\nMAIL FROM:<anne@example.com>\r\n")

        app_transport = mocker.Mock()
        fake_tls = mocker.Mock()
        fake_tls._extra = {"cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)}
        proto._tls_protocol = fake_tls
        proto._original_transport = orig_transport

        # This is the call SSLProtocol makes when the handshake completes.
        proto.connection_made(app_transport)

        try:
            app_transport.close.assert_called_once()
            assert proto._tls_violation_close is True
            # New session, no half-open transaction survives.
            assert proto.envelope.mail_from is None
        finally:
            # Let the cancelled handler coroutine wind down cleanly.
            temp_event_loop.run_until_complete(
                asyncio.gather(handler_task, return_exceptions=True)
            )

        _assert_handler_got_nothing(handler)

    def test_connection_made_kept_without_buffered_data(
        self, temp_event_loop, mocker, ssl_context_server
    ):
        # A well-behaved handshake (nothing pre-buffered) must NOT trip the
        # strict abort even when strict_starttls is enabled.
        handler = RecordingHandler()
        proto = SMTP(
            handler,
            loop=temp_event_loop,
            tls_context=ssl_context_server,
            strict_starttls=True,
        )
        orig_transport = mocker.Mock()
        orig_transport.get_extra_info.return_value = ("127.0.0.1", 12345)
        proto.connection_made(orig_transport)
        handler_task = proto._handler_coroutine

        app_transport = mocker.Mock()
        fake_tls = mocker.Mock()
        fake_tls._extra = {"cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)}
        proto._tls_protocol = fake_tls
        proto._original_transport = orig_transport
        proto.connection_made(app_transport)

        try:
            app_transport.close.assert_not_called()
            assert proto._tls_violation_close is False
            assert proto.session.ssl == fake_tls._extra
            assert proto.session.host_name is None
        finally:
            handler_task.cancel()
            temp_event_loop.run_until_complete(
                asyncio.gather(handler_task, return_exceptions=True)
            )
