import os
import tempfile

import pytest

import johnnycanencrypt.johnnycanencrypt as jce

from .utils import _get_cert_data

DATA = "Kushal loves 🦀"


def test_sign_detached():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    assert signature


def test_sign_verify_bytes():
    "This will test a signed PGP message creation"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", False).decode("utf-8")
    assert signed_data.endswith("-----END PGP MESSAGE-----\n")
    assert DATA not in signed_data
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_bytes(signed_data.encode("utf-8"))


def test_sign_cleartext():
    "This will test a signed cleartext message creation"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", True).decode("utf-8")
    assert signed_data.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    assert DATA in signed_data
    assert signed_data.endswith("-----END PGP SIGNATURE-----\n")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_bytes(signed_data.encode("utf-8"))


def test_sign_verify_file_cleartext():
    "This will sign a file in cleartext"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    tempdir = tempfile.TemporaryDirectory()
    output = os.path.join(tempdir.name, "sign.asc")
    j.sign_file(b"tests/files/text.txt", output.encode("utf-8"), "redhat", True)
    assert os.path.exists(output)
    with open(output) as fobj:
        data = fobj.read()
    assert data.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    assert "🦄🦄🦄" in data
    assert data.endswith("-----END PGP SIGNATURE-----\n")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_file(output.encode("utf-8"))


def test_sign_verify_file():
    "This will sign a file as a PGP message"
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    tempdir = tempfile.TemporaryDirectory()
    # output = os.path.join(tempdir.name, "sign.asc")
    output = "/tmp/sign.asc"
    j.sign_file(b"tests/files/text.txt", output.encode("utf-8"), "redhat", False)
    assert os.path.exists(output)
    with open(output) as fobj:
        data = fobj.read()
    assert data.startswith("-----BEGIN PGP MESSAGE-----")
    assert "🦄🦄🦄" not in data
    assert data.endswith("-----END PGP MESSAGE-----\n")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_file(output.encode("utf-8"))


def test_verify_bytes_detached():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert jp.verify_bytes_detached(DATA.encode("utf-8"), signature.encode("utf-8"))


def test_verify_bytes_detached_must_fail():
    j = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    data2 = DATA + " "
    assert not jp.verify_bytes_detached(
        data2.encode("utf-8"), signature.encode("utf-8")
    )


def test_sign_detached_fail():
    j = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    with pytest.raises(jce.CryptoError):
        signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
