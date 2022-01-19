import pytest

import johnnycanencrypt.johnnycanencrypt as jce

from .utils import _get_cert_data

DATA = "Kushal loves 🦀"


def test_sign():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    assert signature


def test_sign_included():
    "This will test a signed PGP message creation"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", False)
    assert signed_data.endswith("-----END PGP MESSAGE-----\n")
    assert DATA not in signed_data


def test_sign_included_cleartext():
    "This will test a signed cleartext message creation"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", True)
    assert signed_data.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    assert DATA in signed_data
    assert signed_data.endswith("-----END PGP SIGNATURE-----\n")


def test_verify_bytes():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_bytes(DATA.encode("utf-8"), signature.encode("utf-8"))


def test_verify_bytes_must_fail():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    data2 = DATA + " "
    assert not jp.verify_bytes(data2.encode("utf-8"), signature.encode("utf-8"))


def test_sign_fail():
    j = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    with pytest.raises(jce.CryptoError):
        signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
