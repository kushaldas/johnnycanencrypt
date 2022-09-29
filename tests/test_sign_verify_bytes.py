import os

import pytest

import johnnycanencrypt.johnnycanencrypt as jce

from .conftest import BASE_TESTSDIR
from .utils import _get_cert_data

DATA = "Kushal loves 🦀"


def test_sign_detached():
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    assert signature


def test_sign_verify_bytes():
    "This will test a signed PGP message creation"
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", False).decode("utf-8")
    assert signed_data.endswith("-----END PGP MESSAGE-----\n")
    assert DATA not in signed_data
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    assert jp.verify_bytes(signed_data.encode("utf-8"))


def test_sign_cleartext():
    "This will test a signed cleartext message creation"
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    signed_data = j.sign_bytes(DATA.encode("utf-8"), "redhat", True).decode("utf-8")
    assert signed_data.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    assert DATA in signed_data
    assert signed_data.endswith("-----END PGP SIGNATURE-----\n")
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    assert jp.verify_bytes(signed_data.encode("utf-8"))


def test_sign_verify_file_cleartext(tmp_path):
    "This will sign a file in cleartext"
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    output = (tmp_path / "sign.asc").as_posix()
    j.sign_file(
        (BASE_TESTSDIR / "files/text.txt").as_posix().encode(),
        output.encode("utf-8"),
        "redhat",
        True,
    )
    assert os.path.exists(output)
    with open(output) as fobj:
        data = fobj.read()
    assert data.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    assert "🦄🦄🦄" in data
    assert data.endswith("-----END PGP SIGNATURE-----\n")
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    assert jp.verify_file(output.encode("utf-8"))


def test_sign_verify_file(tmp_path):
    "This will sign a file as a PGP message"
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    output = (tmp_path / "sign.asc").as_posix()
    j.sign_file(
        (BASE_TESTSDIR / "files/text.txt").as_posix().encode(),
        output.encode("utf-8"),
        "redhat",
        False,
    )
    assert os.path.exists(output)
    with open(output) as fobj:
        data = fobj.read()
    assert data.startswith("-----BEGIN PGP MESSAGE-----")
    assert "🦄🦄🦄" not in data
    assert data.endswith("-----END PGP MESSAGE-----\n")
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    assert jp.verify_file(output.encode("utf-8"))


def test_sign_from_gpg_verify_file():
    "This will verify a signed message fro gpg"
    jp = jce.Johnny(
        _get_cert_data(BASE_TESTSDIR / "files/store/kushal_updated_key.asc")
    )
    assert jp.verify_file(str(BASE_TESTSDIR / "files/msg.txt.asc").encode("utf-8"))


def test_verify_signed_file(tmp_path):
    "This will verify a signed message from gpg and extract"
    jp = jce.Johnny(
        _get_cert_data(BASE_TESTSDIR / "files/store/kushal_updated_key.asc")
    )
    output = (tmp_path / "result.txt").as_posix()
    assert jp.verify_and_extract_file(
        str(BASE_TESTSDIR / "files/msg.txt.asc").encode("utf-8"), output.encode("utf-8")
    )

    # Now verify the text inside
    with open(output, "rb") as fobj:
        data = fobj.read()
    assert b"I \xe2\x9d\xa4\xef\xb8\x8f Anwesha.\n" == data


def test_verify_bytes_from_signed_message():
    "This will verify a signed message fro gpg"
    jp = jce.Johnny(
        _get_cert_data(BASE_TESTSDIR / "files/store/kushal_updated_key.asc")
    )
    with open(BASE_TESTSDIR / "files/msg.txt.asc", "rb") as fobj:
        data = fobj.read()
    assert b"I \xe2\x9d\xa4\xef\xb8\x8f Anwesha.\n" == jp.verify_and_extract_bytes(data)


def test_sign_from_different_key_file():
    "This will verify a signed message fro gpg"
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    with pytest.raises(jce.CryptoError):
        jp.verify_file(str(BASE_TESTSDIR / "files/msg.txt.asc").encode("utf-8"))


def test_verify_bytes_detached():
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    assert jp.verify_bytes_detached(DATA.encode("utf-8"), signature.encode("utf-8"))


def test_verify_bytes_detached_must_fail():
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/secret.asc"))
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    data2 = DATA + " "
    assert not jp.verify_bytes_detached(
        data2.encode("utf-8"), signature.encode("utf-8")
    )


def test_sign_detached_fail():
    j = jce.Johnny(_get_cert_data(BASE_TESTSDIR / "files/public.asc"))
    with pytest.raises(jce.CryptoError):
        signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
