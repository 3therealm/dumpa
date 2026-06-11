"""parse_verify_output: cert digest + verified schemes from apksigner text."""

from __future__ import annotations

from dumpa.tools.apksigner import parse_verify_output

_SIGNED = """\
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate DN: CN=Android Debug, O=Android, C=US
Signer #1 certificate SHA-256 digest: 0a1b2c3d4e5f6071829304a5b6c7d8e9f0112233445566778899aabbccddeeff
Signer #1 certificate SHA-1 digest: deadbeef
"""


def test_parse_signed() -> None:
    info = parse_verify_output(_SIGNED)
    assert info.cert_sha256 == "0a1b2c3d4e5f6071829304a5b6c7d8e9f0112233445566778899aabbccddeeff"
    assert info.schemes == ("v2", "v3")


def test_parse_empty() -> None:
    info = parse_verify_output("")
    assert info.cert_sha256 is None
    assert info.schemes == ()


def test_parse_no_schemes_true() -> None:
    text = "Verified using v2 scheme (APK Signature Scheme v2): false\n"
    info = parse_verify_output(text)
    assert info.schemes == ()


_V3_SIGNED = """\
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
V3.0 Signer: certificate DN: CN=Android Debug, O=Android, C=US
V3.0 Signer: certificate SHA-256 digest: e594f8b2b2e4edb9c6d2921d81327d8fbedadc4b2dff9e0d5190e784a0e31bc1
V3.0 Signer: certificate SHA-1 digest: 16df16d90d2cfd0be0a4cd8fd5e0191fb6c6f6d7
"""


def test_parse_v3_signer_label() -> None:
    """Newer apksigner uses 'V3.0 Signer:' instead of 'Signer #1'."""
    info = parse_verify_output(_V3_SIGNED)
    assert info.cert_sha256 == "e594f8b2b2e4edb9c6d2921d81327d8fbedadc4b2dff9e0d5190e784a0e31bc1"
    assert info.schemes == ("v1", "v2", "v3")


_RELEASE = """\
Verified using v2 scheme (APK Signature Scheme v2): true
Signer #1 certificate DN: CN=Acme Games Ltd, O=Acme, L=London, C=GB
Signer #1 certificate SHA-256 digest: abc123
"""


def test_debug_cert_detected() -> None:
    """The canonical Android debug DN flags the signer as a debug cert."""
    assert parse_verify_output(_SIGNED).is_debug is True
    assert parse_verify_output(_V3_SIGNED).is_debug is True


def test_release_cert_not_debug() -> None:
    assert parse_verify_output(_RELEASE).is_debug is False


def test_empty_not_debug() -> None:
    assert parse_verify_output("").is_debug is False


def test_debug_dn_order_and_spacing_insensitive() -> None:
    """RDN-set comparison ignores ordering and extra spacing in the DN line."""
    text = "Signer #1 certificate DN: C=US,  O=Android , CN=Android Debug\n"
    assert parse_verify_output(text).is_debug is True
