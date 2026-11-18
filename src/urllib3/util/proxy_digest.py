from __future__ import annotations

import hashlib
import os
import typing
from urllib.parse import quote

from .._collections import HTTPHeaderDict

# RFC 7616 section 3.3: the only characters allowed unescaped inside a
# quoted-string of an Authorization header field.
_QSAFE_CHARS = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) not in '"\\')


class ProxyDigestCredentials(typing.NamedTuple):
    """Username/password pair used to answer an HTTP proxy ``Digest``
    authentication challenge (RFC 7616) received with a ``407`` status.

    Unlike :rfc:`7617` Basic authentication, Digest cannot be carried by a
    static header: the response hash depends on the per-connection
    ``nonce``/``realm`` values advertised by the proxy in its
    ``Proxy-Authenticate`` challenge, so the credentials have to be kept
    around until a challenge actually arrives.
    """

    username: str
    password: str


def _quote(value: str) -> str:
    # RFC 7616 section 3.3 mandates UTF-8 encoding of the quoted value before
    # percent-escaping every byte outside the qdtext-safe set.
    return quote(value.encode("utf-8"), safe=_QSAFE_CHARS)


def _parse_directives(challenge: str) -> dict[str, str]:
    """Parse the directives of a single ``Digest`` challenge value.

    Only a single challenge is supported, matching the subset required for
    proxy authentication. Quoted-string and token directive values are both
    accepted; surrounding quotes are stripped.
    """
    directives: dict[str, str] = {}
    remainder = challenge.strip()
    while remainder:
        # Find the next '=' delimiting a key/value pair.
        equals = remainder.find("=")
        if equals == -1:
            break
        key = remainder[:equals].strip().lower()
        remainder = remainder[equals + 1 :].lstrip()
        if remainder.startswith('"'):
            # Quoted-string value, honoring backslash-escaped characters.
            value_chars: list[str] = []
            index = 1
            while index < len(remainder):
                char = remainder[index]
                if char == "\\" and index + 1 < len(remainder):
                    value_chars.append(remainder[index + 1])
                    index += 2
                elif char == '"':
                    index += 1
                    break
                else:
                    value_chars.append(char)
                    index += 1
            value = "".join(value_chars)
            remainder = remainder[index:].lstrip()
            if remainder.startswith(","):
                remainder = remainder[1:].lstrip()
        else:
            comma = remainder.find(",")
            if comma == -1:
                value = remainder.strip()
                remainder = ""
            else:
                value = remainder[:comma].strip()
                remainder = remainder[comma + 1 :].lstrip()
        if key:
            directives[key] = value
    return directives


def build_proxy_digest_authorization(
    challenge: str,
    credentials: ProxyDigestCredentials,
    method: str,
    uri: str,
) -> str | None:
    """Build a ``Proxy-Authorization: Digest ...`` header answering ``challenge``.

    The challenge is the value of a ``Proxy-Authenticate`` response header
    (without the leading ``Digest`` scheme). Only the MD5 algorithm family
    (``MD5``/``MD5-sess``) combined with the ``auth`` quality-of-protection
    subset from RFC 7616 is implemented. ``None`` is returned for challenges
    outside that subset so callers preserve their existing failure behavior.
    """
    scheme, _, params = challenge.strip().partition(" ")
    if scheme.lower() != "digest":
        return None

    directives = _parse_directives(params)
    realm = directives.get("realm")
    nonce = directives.get("nonce")
    if realm is None or nonce is None:
        return None

    algorithm = directives.get("algorithm", "MD5").upper()
    if algorithm not in ("MD5", "MD5-SESS"):
        return None

    qop_header = directives.get("qop")
    if qop_header:
        offered_qops = [part.strip().lower() for part in qop_header.split(",")]
        if "auth" not in offered_qops:
            # 'auth-int' and unknown qop values are outside the implemented
            # RFC 7616 subset.
            return None
        qop = "auth"
    else:
        qop = ""

    def md5_hex(*parts: str) -> str:
        return hashlib.md5(":".join(parts).encode("utf-8")).hexdigest()

    ha1 = md5_hex(credentials.username, realm, credentials.password)
    if algorithm == "MD5-SESS":
        cnonce = os.urandom(16).hex()
        ha1 = md5_hex(ha1, nonce, cnonce)
    else:
        cnonce = os.urandom(16).hex()

    ha2 = md5_hex(method.upper(), uri)

    if qop:
        nonce_count = 1
        nc = f"{nonce_count:08x}"
        response = md5_hex(ha1, nonce, nc, cnonce, qop, ha2)
    else:
        # RFC 2069 legacy form, still permitted by RFC 7616 when the
        # challenge omits qop entirely.
        nc = ""
        response = md5_hex(ha1, nonce, ha2)

    fields = [
        ("username", credentials.username),
        ("realm", realm),
        ("nonce", nonce),
        ("uri", uri),
        ("response", response),
        ("algorithm", algorithm),
    ]
    if qop:
        fields.extend((("qop", qop), ("nc", nc), ("cnonce", cnonce)))
    opaque = directives.get("opaque")
    if opaque is not None:
        fields.append(("opaque", opaque))

    header_value = ", ".join(f'{key}="{_quote(value)}"' for key, value in fields)
    return f"Digest {header_value}"


def extract_digest_challenge(headers: HTTPHeaderDict | typing.Any) -> str | None:
    """Return the first ``Digest`` challenge advertised in
    ``Proxy-Authenticate`` headers, or ``None`` if there is none.

    A proxy may advertise multiple authentication schemes; only a
    ``Digest`` one can be answered by this module.
    """
    raw = headers.get("proxy-authenticate") if headers is not None else None
    if not raw:
        return None
    # Multiple Proxy-Authenticate headers may have been folded into one
    # comma-separated field, but a Digest challenge itself contains commas,
    # so locate the scheme by prefix scan instead of naively splitting.
    for value in HTTPHeaderDict(headers).getlist("proxy-authenticate"):
        scheme = value.split(" ", 1)[0].strip().lower()
        if scheme == "digest":
            return value
    return None
