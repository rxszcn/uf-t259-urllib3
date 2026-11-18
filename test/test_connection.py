from __future__ import annotations

import datetime
import io
import socket
import typing
from http.client import HTTPMessage, ResponseNotReady
from unittest import mock

import pytest

from urllib3._base_connection import ProxyConfig
from urllib3.connection import (  # type: ignore[attr-defined]
    RECENT_DATE,
    CertificateError,
    HTTPConnection,
    HTTPSConnection,
    _match_hostname,
    _normalize_header_value,
    _normalize_header_values,
    _url_from_connection,
    _wrap_proxy_error,
)
from urllib3.exceptions import HTTPError, ProxyError, SSLError
from urllib3.util import ssl_
from urllib3.util.proxy_digest import (
    ProxyDigestCredentials,
    _parse_directives,
)
from urllib3.util.request import SKIP_HEADER
from urllib3.util.ssl_match_hostname import (
    CertificateError as ImplementationCertificateError,
)
from urllib3.util.ssl_match_hostname import _dnsname_match, match_hostname
from urllib3.util.url import parse_url

if typing.TYPE_CHECKING:
    from urllib3.util.ssl_ import _TYPE_PEER_CERT_RET_DICT


class _SequentialProxySocket:
    """Fake socket replaying scripted proxy CONNECT responses.

    Every new connection (``_new_conn`` call) pops the next raw HTTP response
    from ``responses`` and exposes a fresh ``makefile()`` stream over it,
    while recording every CONNECT request sent on the wire.
    """

    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.sent_requests: list[bytes] = []
        self.closed = False
        self.timeout: float | None = None
        self._current = b""

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def connect(self) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.send(data)

    def send(self, data: bytes) -> int:
        self.sent_requests.append(data)
        return len(data)

    def makefile(self, *args: typing.Any, **kwargs: typing.Any) -> io.BytesIO:
        return io.BytesIO(self._current)

    def close(self) -> None:
        self.closed = True

    def shutdown(self, flag: int) -> None:
        pass

    def pop_next(self) -> "_SequentialProxySocket":
        # Each _new_conn call returns the same object, armed with the next
        # scripted response.
        self._current = self._responses.pop(0)
        self.closed = False
        return self


_PROXY_DIGEST_CHALLENGE = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Digest realm="proxy-realm", '
    b'qop="auth", nonce="deadbeefnonce", '
    b'opaque="opaque-value"\r\n'
    b"Content-Length: 0\r\n\r\n"
)
_PROXY_TUNNEL_OK = b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"


def _tunnel_connection(
    credentials: ProxyDigestCredentials | None,
) -> tuple[HTTPConnection, _SequentialProxySocket]:
    proxy = parse_url("http://proxy.example:3128")
    # The connection's host is the proxy itself; the target is declared
    # solely via set_tunnel(), matching HTTPSConnectionPool wiring.
    conn = HTTPConnection(
        "proxy.example",
        port=3128,
        proxy=proxy,
        proxy_config=ProxyConfig(None, False, None, None, credentials),
    )
    conn.set_tunnel("target.example", 443, scheme="http")
    fake_sock = _SequentialProxySocket([_PROXY_DIGEST_CHALLENGE, _PROXY_TUNNEL_OK])
    conn._new_conn = lambda: fake_sock.pop_next()  # type: ignore[method-assign]
    return conn, fake_sock


class TestConnection:
    """
    Tests in this suite should not make any network requests or connections.
    """

    def test_match_hostname_no_cert(self) -> None:
        cert = None
        asserted_hostname = "foo"
        with pytest.raises(ValueError):
            _match_hostname(cert, asserted_hostname)

    def test_match_hostname_empty_cert(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {}
        asserted_hostname = "foo"
        with pytest.raises(ValueError):
            _match_hostname(cert, asserted_hostname)

    def test_match_hostname_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo"),)}
        asserted_hostname = "foo"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_mismatch(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo"),)}
        asserted_hostname = "bar"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname 'bar' doesn't match 'foo'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "bar",
                {"subjectAltName": (("DNS", "foo"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_no_dns(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", ""),)}
        asserted_hostname = "bar"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname 'bar' doesn't match ''" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "bar",
                {"subjectAltName": (("DNS", ""),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_startwith_wildcard(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "*"),)}
        asserted_hostname = "foo"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_dnsname(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("DNS", "xn--p1b6ci4b4b3a*.xn--11b5bs8d"),)
        }
        asserted_hostname = "xn--p1b6ci4b4b3a*.xn--11b5bs8d"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_include_wildcard(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo*"),)}
        asserted_hostname = "foobar"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_more_than_one_dnsname_error(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("DNS", "foo*"), ("DNS", "fo*"))
        }
        asserted_hostname = "bar"
        with pytest.raises(CertificateError, match="doesn't match either of"):
            _match_hostname(cert, asserted_hostname)

    def test_dnsname_match_include_more_than_one_wildcard_error(self) -> None:
        with pytest.raises(CertificateError, match="too many wildcards in certificate"):
            _dnsname_match("foo**", "foobar")

    def test_match_hostname_ignore_common_name(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subject": ((("commonName", "foo"),),)}
        asserted_hostname = "foo"
        with pytest.raises(
            ImplementationCertificateError,
            match="no appropriate subjectAltName fields were found",
        ):
            match_hostname(cert, asserted_hostname)

    def test_match_hostname_check_common_name(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subject": ((("commonName", "foo"),),)}
        asserted_hostname = "foo"
        match_hostname(cert, asserted_hostname, True)

    def test_match_hostname_ip_address(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1.1.1.1"),)
        }
        asserted_hostname = "1.1.1.2"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname '1.1.1.2' doesn't match '1.1.1.1'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "1.1.1.2",
                {"subjectAltName": (("IP Address", "1.1.1.1"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        ["asserted_hostname", "san_ip"],
        [
            ("1:2::3:4", "1:2:0:0:0:0:3:4"),
            ("1:2:0:0::3:4", "1:2:0:0:0:0:3:4"),
            ("::0.1.0.2", "0:0:0:0:0:0:1:2"),
            ("::1%42", "0:0:0:0:0:0:0:1"),
            ("::2%iface", "0:0:0:0:0:0:0:2"),
        ],
    )
    def test_match_hostname_ip_address_ipv6(
        self, asserted_hostname: str, san_ip: str
    ) -> None:
        """Check that hostname matches follow RFC 9110 rules for IPv6."""
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("IP Address", san_ip),)}
        match_hostname(cert, asserted_hostname)

    def test_match_hostname_ip_address_ipv6_doesnt_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1:2::2:1"),)
        }
        asserted_hostname = "1:2::2:2"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname '1:2::2:2' doesn't match '1:2::2:1'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "1:2::2:2",
                {"subjectAltName": (("IP Address", "1:2::2:1"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_dns_with_brackets_doesnt_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (
                ("DNS", "localhost"),
                ("IP Address", "localhost"),
            )
        }
        asserted_hostname = "[localhost]"
        with pytest.raises(CertificateError) as e:
            _match_hostname(cert, asserted_hostname)
        assert (
            "hostname '[localhost]' doesn't match either of 'localhost', 'localhost'"
            in str(e.value)
        )

    def test_match_hostname_ip_address_ipv6_brackets(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1:2::2:1"),)
        }
        asserted_hostname = "[1:2::2:1]"
        # Assert no error is raised
        _match_hostname(cert, asserted_hostname)

    def test_recent_date(self) -> None:
        # This test is to make sure that the RECENT_DATE value
        # doesn't get too far behind what the current date is.
        # When this test fails update urllib3.connection.RECENT_DATE
        # according to the rules defined in that file.
        two_years = datetime.timedelta(days=365 * 2)
        assert RECENT_DATE > (datetime.datetime.today() - two_years).date()

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("ordinary\tvalue", "ordinary\tvalue"),
            ("before \t\r\n\t  after", "before after"),
            ("one\r\n two\t\r\n\tthree", "one two three"),
            ("one\r\n \r\n\tthree", "one  three"),
            # A bare CR or LF is not an obs-fold; each one is replaced with SP.
            ("one\n two", "one  two"),
            ("one\r two", "one  two"),
            ("value\ninjected", "value injected"),
            ("value\rinjected", "value injected"),
            ("one\r\n\ttwo\n three", "one two  three"),
            # NUL is replaced with SP as well.
            ("value\x00injected", "value injected"),
            # Leading and trailing SP and HTAB are trimmed.
            (" \tvalue\t ", "value"),
            ("value \r\n ", "value"),
            ("value\x00", "value"),
            (" \t", ""),
        ],
    )
    def test_normalize_header_value(self, value: str, expected: str) -> None:
        assert _normalize_header_value(value) == expected

    def test_normalize_header_values_preserves_message(self) -> None:
        message = HTTPMessage()
        message["X-First"] = "one"
        message["Set-Cookie"] = "a=1 \r\n two"
        message["X-Second"] = "three"
        message["Set-Cookie"] = "b=2"
        message.set_payload("payload")
        defects = message.defects
        policy = message.policy

        header_items = _normalize_header_values(message)

        expected = [
            ("X-First", "one"),
            ("Set-Cookie", "a=1 two"),
            ("X-Second", "three"),
            ("Set-Cookie", "b=2"),
        ]
        assert header_items == expected
        assert message.items() == expected
        assert message.get_all("Set-Cookie") == ["a=1 two", "b=2"]
        assert message.get_payload() == "payload"
        assert message.defects is defects
        assert message.policy is policy

    def test_HTTPSConnection_default_socket_options(self) -> None:
        conn = HTTPSConnection("not.a.real.host", port=443)
        assert conn.socket_options == [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]

    @pytest.mark.parametrize(
        "proxy_scheme, err_part",
        [
            ("http", "Unable to connect to proxy"),
            (
                "https",
                "Unable to connect to proxy. Your proxy appears to only use HTTP and not HTTPS",
            ),
        ],
    )
    def test_wrap_proxy_error(self, proxy_scheme: str, err_part: str) -> None:
        new_err = _wrap_proxy_error(HTTPError("unknown protocol"), proxy_scheme)
        assert isinstance(new_err, ProxyError) is True
        assert err_part in new_err.args[0]

    def test_url_from_pool(self) -> None:
        conn = HTTPConnection("google.com", port=80)

        path = "path?query=foo"
        assert f"http://google.com:80/{path}" == _url_from_connection(conn, path)

    def test_getresponse_requires_reponseoptions(self) -> None:
        conn = HTTPConnection("google.com", port=80)

        # Should error if a request has not been sent
        with pytest.raises(ResponseNotReady):
            conn.getresponse()

    def test_assert_fingerprint_closes_socket(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.wrap_socket.return_value.getpeercert.return_value = b"fake cert"
        conn = HTTPSConnection(
            "google.com",
            port=443,
            assert_fingerprint="AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA",
            ssl_context=context,
        )
        with mock.patch.object(conn, "_new_conn"):
            with pytest.raises(SSLError):
                conn.connect()

        context.wrap_socket.return_value.close.assert_called_once_with()

    def test_assert_hostname_closes_socket(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.wrap_socket.return_value.getpeercert.return_value = {
            "subjectAltName": (("DNS", "google.com"),)
        }
        conn = HTTPSConnection(
            "google.com", port=443, assert_hostname="example.com", ssl_context=context
        )
        with mock.patch.object(conn, "_new_conn"):
            with pytest.raises(ImplementationCertificateError):
                conn.connect()

        context.wrap_socket.return_value.close.assert_called_once_with()

    @pytest.mark.parametrize(
        "accept_encoding",
        [
            "Accept-Encoding",
            "accept-encoding",
            b"Accept-Encoding",
            b"accept-encoding",
            None,
        ],
    )
    @pytest.mark.parametrize("host", ["Host", "host", b"Host", b"host", None])
    @pytest.mark.parametrize(
        "user_agent", ["User-Agent", "user-agent", b"User-Agent", b"user-agent", None]
    )
    @pytest.mark.parametrize("chunked", [True, False])
    def test_skip_header(
        self,
        accept_encoding: str | None,
        host: str | None,
        user_agent: str | None,
        chunked: bool,
    ) -> None:
        headers = {}
        if accept_encoding is not None:
            headers[accept_encoding] = SKIP_HEADER
        if host is not None:
            headers[host] = SKIP_HEADER
        if user_agent is not None:
            headers[user_agent] = SKIP_HEADER

        with (
            mock.patch("urllib3.util.connection.create_connection"),
            mock.patch(
                "urllib3.connection._HTTPConnection.putheader"
            ) as http_client_putheader,
        ):
            conn = HTTPConnection("")
            conn.request("GET", "/headers", headers=headers, chunked=chunked)

        request_headers = {}
        for call in http_client_putheader.call_args_list:
            header, value = call.args
            request_headers[header] = value

        if accept_encoding is None:
            assert "Accept-Encoding" in request_headers
        else:
            assert accept_encoding not in request_headers
        if host is None:
            assert "Host" in request_headers
        else:
            assert host not in request_headers
        if user_agent is None:
            assert "User-Agent" in request_headers
        else:
            assert user_agent not in request_headers

    def test_putheader_multiple_values(self) -> None:
        with mock.patch(
            "urllib3.connection._HTTPConnection.putheader"
        ) as http_client_putheader:
            conn = HTTPConnection("")
            conn.putheader("X-Test", "a", "b")

        http_client_putheader.assert_called_once_with("X-Test", "a", "b")

    def test_tunnel_proxy_digest_407_rebuilds_tunnel(self) -> None:
        """A 407 Digest challenge during CONNECT is answered and the tunnel
        is rebuilt on a fresh socket with Proxy-Authorization on the wire."""
        credentials = ProxyDigestCredentials("proxy-user", "proxy-pass")
        conn, fake_sock = _tunnel_connection(credentials)

        conn.connect()

        assert conn.is_closed is False
        assert conn.has_connected_to_proxy is True
        # Two CONNECT exchanges: the bare one, then the authenticated retry.
        assert len(fake_sock.sent_requests) == 2
        first_request, second_request = fake_sock.sent_requests
        assert b"CONNECT target.example:443" in first_request
        assert b"Proxy-Authorization" not in first_request
        assert b"CONNECT target.example:443" in second_request
        assert b"Proxy-Authorization: Digest " in second_request

        digest_header = next(
            line
            for line in second_request.split(b"\r\n")
            if line.startswith(b"Proxy-Authorization: Digest ")
        ).decode("latin-1")
        directives = _parse_directives(
            digest_header.removeprefix("Proxy-Authorization: Digest ")
        )
        assert directives["username"] == "proxy-user"
        assert directives["realm"] == "proxy-realm"
        assert directives["nonce"] == "deadbeefnonce"
        assert directives["opaque"] == "opaque-value"
        assert directives["qop"] == "auth"
        assert directives["nc"] == "00000001"
        assert directives["algorithm"] == "MD5"
        assert directives["uri"] == "target.example:443"

        import hashlib

        ha1 = hashlib.md5(b"proxy-user:proxy-realm:proxy-pass").hexdigest()
        ha2 = hashlib.md5(b"CONNECT:target.example:443").hexdigest()
        expected_response = hashlib.md5(
            f"{ha1}:deadbeefnonce:00000001:{directives['cnonce']}:auth:{ha2}".encode()
        ).hexdigest()
        assert directives["response"] == expected_response
        conn.close()

    def test_tunnel_without_proxy_digest_credentials_keeps_failure(self) -> None:
        """Without configured credentials a 407 on CONNECT fails with the
        historical tunnel error and no Proxy-Authorization header is sent."""
        conn, fake_sock = _tunnel_connection(None)

        with pytest.raises(OSError, match="Tunnel connection failed: 407"):
            conn.connect()

        assert len(fake_sock.sent_requests) == 1
        assert b"Proxy-Authorization" not in fake_sock.sent_requests[0]
        assert conn.is_closed is True

    def test_tunnel_unsupported_digest_challenge_keeps_failure(self) -> None:
        """A challenge outside the MD5/auth subset behaves like no creds."""
        conn = HTTPConnection(
            "proxy.example",
            port=3128,
            proxy=parse_url("http://proxy.example:3128"),
            proxy_config=ProxyConfig(
                None,
                False,
                None,
                None,
                ProxyDigestCredentials("proxy-user", "proxy-pass"),
            ),
        )
        conn.set_tunnel("target.example", 443, scheme="http")
        unsupported = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Digest realm="r", nonce="n", '
            b'qop="auth-int"\r\nContent-Length: 0\r\n\r\n'
        )
        fake_sock = _SequentialProxySocket([unsupported])
        conn._new_conn = lambda: fake_sock.pop_next()  # type: ignore[method-assign]

        with pytest.raises(OSError, match="Tunnel connection failed: 407"):
            conn.connect()
        assert b"Proxy-Authorization" not in fake_sock.sent_requests[0]
        conn.close()
