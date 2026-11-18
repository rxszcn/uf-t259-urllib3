from __future__ import annotations

from unittest.mock import patch

import pytest

from urllib3._collections import HTTPHeaderDict
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import (
    LocationParseError,
    MaxRetryError,
    NewConnectionError,
    ProxyError,
)
from urllib3.poolmanager import ProxyManager
from urllib3.response import HTTPResponse
from urllib3.util.proxy_digest import ProxyDigestCredentials, _parse_directives
from urllib3.util.retry import Retry
from urllib3.util.url import parse_url

from .port_helpers import find_unused_port

_PROXY_DIGEST_CHALLENGE_HEADER = (
    'Digest realm="proxy-realm", qop="auth", '
    'nonce="deadbeefnonce", opaque="opaque-value"'
)


class TestProxyManager:
    @pytest.mark.parametrize(
        "proxy_scheme, scheme",
        [("http", "http"), ("https", "http"), ("https", "https")],
    )
    @pytest.mark.parametrize("zone", ["1", "25", "251", "25ethA", "et%61"])
    @pytest.mark.parametrize("retry_kind", [None, "status", "connection"])
    def test_scoped_ipv6_request_target_matches_host(
        self, proxy_scheme: str, scheme: str, zone: str, retry_kind: str | None
    ) -> None:
        responses: list[HTTPResponse | Exception] = []
        if retry_kind == "status":
            responses.extend([HTTPResponse(status=503), HTTPResponse(status=503)])
        elif retry_kind == "connection":
            responses.extend([OSError("connection reset"), OSError("connection reset")])
        responses.append(HTTPResponse(status=200))

        with ProxyManager(
            f"{proxy_scheme}://proxy:8080", use_forwarding_for_https=True
        ) as manager:
            with patch.object(
                HTTPConnectionPool,
                "_make_request",
                side_effect=responses,
            ) as request:
                response = manager.urlopen(
                    "GET",
                    f"{scheme}://[FE80::1%25{zone}]:8080/path?x=%23#fragment",
                    retries=Retry(total=2, status_forcelist=[503]),
                )

        assert response.status == 200
        assert request.call_count == len(responses)
        for call in request.call_args_list:
            assert call.args[2] == f"{scheme}://[fe80::1%{zone}]:8080/path?x=%23"
            assert call.kwargs["headers"]["Host"] == f"[fe80::1%{zone}]:8080"

    @pytest.mark.parametrize("proxy_scheme", ["http", "https"])
    def test_proxy_headers(self, proxy_scheme: str) -> None:
        url = "http://pypi.org/project/urllib3/"
        proxy_url = f"{proxy_scheme}://something:1234"
        with ProxyManager(proxy_url) as p:
            # Verify default headers
            default_headers = {"Accept": "*/*", "Host": "pypi.org"}
            headers = p._set_proxy_headers(url)

            assert headers == default_headers

            # Verify default headers don't overwrite provided headers
            provided_headers = {
                "Accept": "application/json",
                "custom": "header",
                "Host": "test.python.org",
            }
            headers = p._set_proxy_headers(url, provided_headers)

            assert headers == provided_headers

            # Verify proxy with nonstandard port
            provided_headers = {"Accept": "application/json"}
            expected_headers = provided_headers.copy()
            expected_headers.update({"Host": "pypi.org:8080"})
            url_with_port = "http://pypi.org:8080/project/urllib3/"
            headers = p._set_proxy_headers(url_with_port, provided_headers)

            assert headers == expected_headers

    def test_default_port(self) -> None:
        with ProxyManager("http://something") as p:
            assert p.proxy is not None
            assert p.proxy.port == 80
        with ProxyManager("https://something") as p:
            assert p.proxy is not None
            assert p.proxy.port == 443

    def test_proxy_port_zero(self) -> None:
        with ProxyManager("http://proxy:0") as p:
            assert p.proxy is not None
            assert p.proxy.port == 0

    def test_invalid_scheme(self) -> None:
        with pytest.raises(AssertionError):
            ProxyManager("invalid://host/p")
        with pytest.raises(ValueError):
            ProxyManager("invalid://host/p")

    def test_proxy_tunnel(self) -> None:
        http_url = parse_url("http://example.com")
        https_url = parse_url("https://example.com")
        with ProxyManager("http://proxy:8080") as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url) is False

        with ProxyManager("https://proxy:8080") as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url) is False

        with ProxyManager("https://proxy:8080", use_forwarding_for_https=True) as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url)

    @pytest.mark.parametrize("proxy_scheme", ["http", "https"])
    def test_absolute_form_request_target_strips_fragment_for_custom_pool(
        self, proxy_scheme: str
    ) -> None:
        class CustomConnectionPool:
            requested_urls: list[str] = []

            def __init__(self, host: str, port: int | None = None, **kw: object):
                pass

            def urlopen(self, method: str, url: str, **kw: object) -> HTTPResponse:
                self.requested_urls.append(url)
                return HTTPResponse(status=200)

        with ProxyManager(f"{proxy_scheme}://proxy:8080") as p:
            p.pool_classes_by_scheme = p.pool_classes_by_scheme.copy()
            p.pool_classes_by_scheme[proxy_scheme] = CustomConnectionPool
            response = p.urlopen(
                "GET",
                "http://example.com/path?x=1#marker=value",
            )

        assert response.status == 200
        assert CustomConnectionPool.requested_urls == ["http://example.com/path?x=1"]

    @pytest.mark.parametrize(
        "url",
        [
            "https://victim.example\r\nInjected/path",
            "https://[::1%25%0d%0a]/",
        ],
    )
    def test_proxy_connect_rejects_control_characters_in_tunnel_host(
        self, url: str
    ) -> None:
        with ProxyManager("http://proxy:8080") as p:
            with pytest.raises(LocationParseError):
                p.connection_from_url(url)

    @pytest.mark.parametrize("host", ["foo%.example", "foo%zz.example"])
    def test_proxy_connect_rejects_malformed_percent_escapes_in_tunnel_host(
        self, host: str
    ) -> None:
        with ProxyManager("http://proxy:8080") as p:
            with pytest.raises(LocationParseError):
                p.connection_from_host(host, scheme="https")

    def test_proxy_connect_retry(self) -> None:
        retry = Retry(total=None, connect=False)
        port = find_unused_port()
        with ProxyManager(f"http://localhost:{port}") as p:
            with pytest.raises(ProxyError) as ei:
                p.urlopen("HEAD", url="http://localhost/", retries=retry)
            assert isinstance(ei.value.original_error, NewConnectionError)

        retry = Retry(total=None, connect=2)
        with ProxyManager(f"http://localhost:{port}") as p:
            with pytest.raises(MaxRetryError) as ei1:
                p.urlopen("HEAD", url="http://localhost/", retries=retry)
            assert ei1.value.reason is not None
            assert isinstance(ei1.value.reason, ProxyError)
            assert isinstance(ei1.value.reason.original_error, NewConnectionError)

    def test_forwarding_proxy_digest_407_answers_and_resends(self) -> None:
        """A 407 on a forwarded request is answered with Digest credentials
        and the request is re-sent carrying Proxy-Authorization."""
        challenge_response = HTTPResponse(
            status=407,
            headers=HTTPHeaderDict(
                {"Proxy-Authenticate": _PROXY_DIGEST_CHALLENGE_HEADER}
            ),
        )
        success_response = HTTPResponse(status=200)

        credentials = ProxyDigestCredentials("proxy-user", "proxy-pass")
        with ProxyManager(
            "http://proxy:8080", proxy_digest_credentials=credentials
        ) as manager:
            assert manager.proxy_config.proxy_digest_credentials is credentials
            with patch.object(
                HTTPConnectionPool,
                "_make_request",
                side_effect=[challenge_response, success_response],
            ) as request:
                response = manager.urlopen(
                    "GET", "http://example.com/path?x=1", retries=0
                )

        assert response.status == 200
        assert request.call_count == 2
        # The first request carries no Proxy-Authorization header.
        first_headers = request.call_args_list[0].kwargs["headers"]
        assert "Proxy-Authorization" not in first_headers

        second_headers = request.call_args_list[1].kwargs["headers"]
        digest_header = second_headers["Proxy-Authorization"]
        assert digest_header.startswith("Digest ")
        directives = _parse_directives(digest_header.removeprefix("Digest "))
        assert directives["username"] == "proxy-user"
        assert directives["realm"] == "proxy-realm"
        assert directives["nonce"] == "deadbeefnonce"
        assert directives["opaque"] == "opaque-value"
        assert directives["qop"] == "auth"
        assert directives["nc"] == "00000001"
        assert directives["algorithm"] == "MD5"
        # In forwarding mode the digest URI is the absolute-form request target.
        assert directives["uri"] == "http://example.com/path?x=1"

        import hashlib

        ha1 = hashlib.md5(b"proxy-user:proxy-realm:proxy-pass").hexdigest()
        ha2 = hashlib.md5(b"GET:http://example.com/path?x=1").hexdigest()
        expected = hashlib.md5(
            f"{ha1}:deadbeefnonce:00000001:{directives['cnonce']}:auth:{ha2}".encode()
        ).hexdigest()
        assert directives["response"] == expected

    def test_forwarding_proxy_407_without_credentials_passes_through(self) -> None:
        """Without Digest credentials the proxy's 407 is returned to the
        caller exactly as before, with no authentication retry."""
        challenge_response = HTTPResponse(
            status=407,
            headers=HTTPHeaderDict(
                {"Proxy-Authenticate": _PROXY_DIGEST_CHALLENGE_HEADER}
            ),
        )
        with ProxyManager("http://proxy:8080") as manager:
            assert manager.proxy_config.proxy_digest_credentials is None
            with patch.object(
                HTTPConnectionPool,
                "_make_request",
                return_value=challenge_response,
            ) as request:
                response = manager.urlopen("GET", "http://example.com/", retries=0)

        assert response.status == 407
        assert response.headers["Proxy-Authenticate"] == _PROXY_DIGEST_CHALLENGE_HEADER
        assert request.call_count == 1
        assert "Proxy-Authorization" not in request.call_args.kwargs["headers"]
