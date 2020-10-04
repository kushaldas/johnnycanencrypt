import os
import tempfile
import johnnycanencrypt as jce
import pytest


def setup_module(module):
    module.tmpdirname = tempfile.TemporaryDirectory()


def teardown_module(module):
    del module.tmpdirname


def test_correct_keystore_path():
    ks = jce.KeyStore("tests/files/store")


def test_nonexisting_keystore_path():
    with pytest.raises(OSError):
        ks = jce.KeyStore("tests/files2/")


def test_no_such_key():
    with pytest.raises(jce.KeyNotFoundError):
        ks = jce.KeyStore("tests/files/store")
        key = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED677")


def test_keystore_lifecycle():
    ks = jce.KeyStore(tmpdirname.name)
    newkey = ks.create_newkey("redhat", "test key1 <email@example.com>", "RSA4k")
    # the default key must be of public
    assert newkey.keytype == "public"
    fingerprint = newkey.fingerprint
    # Keys should be on disk
    assert os.path.exists(os.path.join(tmpdirname.name, f"{fingerprint}.pub"))
    assert os.path.exists(os.path.join(tmpdirname.name, f"{fingerprint}.sec"))

    # Get the key from disk

    k = ks.get_key(fingerprint)
    assert k.keytype == "public"
    assert k.keypath == newkey.keypath
    ks.import_cert("tests/files/store/public.asc")
    ks.import_cert("tests/files/store/pgp_keys.asc")
    ks.import_cert("tests/files/store/hellopublic.asc")
    ks.import_cert("tests/files/store/secret.asc")
    # Now check the numbers of keys in the store
    assert (4, 2) == ks.details()


def test_keystore_details():
    ks = jce.KeyStore("./tests/files/store")
    assert (3, 2) == ks.details()
