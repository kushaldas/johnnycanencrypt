import datetime
import os
import shutil
import tempfile

import pytest

import johnnycanencrypt as jce

from .utils import clean_outputfiles, verify_files

DATA = "Kushal loves 🦀"


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
        key = ks.get_key("A4F388BBB194925AE301F844C52B42177857DD79")


def test_keystore_lifecycle():
    ks = jce.KeyStore(tmpdirname.name)
    newkey = ks.create_newkey(
        "redhat", "test key1 <email@example.com>", jce.Cipher.RSA4k
    )
    # the default key must be of secret
    assert newkey.keytype == jce.KeyType.SECRET

    ks.import_cert("tests/files/store/public.asc")
    ks.import_cert("tests/files/store/pgp_keys.asc")
    ks.import_cert("tests/files/store/hellopublic.asc")
    ks.import_cert("tests/files/store/secret.asc")
    # Now check the numbers of keys in the store
    assert (2, 2) == ks.details()

    ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert (2, 1) == ks.details()

    # Now verify email cache
    key_via_fingerprint = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys_via_emails = ks.get_keys(qvalue="kushaldas@gmail.com", qtype="email")
    assert len(keys_via_emails) == 1
    assert key_via_fingerprint == keys_via_emails[0]

    # Now verify name cache
    key_via_fingerprint = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    keys_via_names = ks.get_keys(qvalue="Test User2 <random@example.com>", qtype="value")
    assert len(keys_via_names) == 1
    assert key_via_fingerprint == keys_via_names[0]


def test_keystore_contains_key():
    "verifies __contains__ method for keystore"
    ks = jce.KeyStore(tmpdirname.name)
    keypath = "tests/files/store/secret.asc"
    k = ks.import_cert(keypath)
    _, fingerprint, keytype, exp, ctime = jce.parse_cert_file(keypath)

    # First only the fingerprint
    assert fingerprint in ks
    # Next the Key object
    assert k in ks
    # This should be false
    assert not "1111111" in ks


def test_keystore_details():
    ks = jce.KeyStore("./tests/files/store")
    assert (1, 2) == ks.details()


def test_keystore_key_uids():
    ks = jce.KeyStore("./tests/files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert "kushal@fedoraproject.org" == key.uids[0]["email"]
    assert "mail@kushaldas.in" == key.uids[-1]["email"]


def test_key_deletion():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    ks.import_cert("tests/files/store/public.asc")
    k = ks.import_cert("tests/files/store/pgp_keys.asc")
    ks.import_cert("tests/files/store/hellopublic.asc")
    ks.import_cert("tests/files/store/hellosecret.asc")
    ks.import_cert("tests/files/store/secret.asc")
    assert (1, 2) == ks.details()

    ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert (1, 1) == ks.details()

    # Now send in a Key object
    ks.delete_key(k)
    assert (0, 1) == ks.details()
    with pytest.raises(jce.KeyNotFoundError):
        ks.delete_key("11111")

    # Can not use any random data type
    with pytest.raises(TypeError):
        ks.delete_key(2441139)


def test_key_equality():
    ks = jce.KeyStore("tests/files/store")
    key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert key.fingerprint == "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"


def test_ks_encrypt_decrypt_bytes():
    "Encrypts and decrypt some bytes"
    ks = jce.KeyStore("tests/files/store")
    public_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    encrypted = ks.encrypt(public_key, DATA)
    assert encrypted.startswith(b"-----BEGIN PGP MESSAGE-----\n")
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_bytes_multiple_recipients():
    "Encrypts and decrypt some bytes"
    ks = jce.KeyStore("tests/files/store")
    key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    encrypted = ks.encrypt([key1, key2], DATA)
    assert encrypted.startswith(b"-----BEGIN PGP MESSAGE-----\n")
    secret_key1 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    decrypted_text = ks.decrypt(secret_key1, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text
    secret_key2 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key2, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_bytes_to_file():
    "Encrypts and decrypt some bytes"
    outputfile = os.path.join(tmpdirname.name, "encrypted.asc")
    ks = jce.KeyStore("tests/files/store")
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert ks.encrypt(secret_key, DATA, outputfile=outputfile)
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_bytes_to_file_multiple_recipients():
    "Encrypts and decrypt some bytes"
    outputfile = os.path.join(tmpdirname.name, "encrypted.asc")
    ks = jce.KeyStore("tests/files/store")
    key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert ks.encrypt([key1, key2], DATA, outputfile=outputfile)
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_file(encrypt_decrypt_file):
    "Encrypts and decrypt some bytes"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"

    ks = jce.KeyStore("tests/files/store")
    public_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert ks.encrypt_file(public_key, inputfile, output)
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    ks.decrypt_file(secret_key, output, decrypted_output, password="redhat")
    verify_files(inputfile, decrypted_output)


def test_ks_encrypt_decrypt_file_multiple_recipients(encrypt_decrypt_file):
    "Encrypts and decrypt some bytes"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"

    ks = jce.KeyStore("tests/files/store")
    key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    encrypted = ks.encrypt_file([key1, key2], inputfile, output)
    secret_key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    ks.decrypt_file(secret_key1, output, decrypted_output, password="redhat")
    verify_files(inputfile, decrypted_output)
    secret_key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    ks.decrypt_file(secret_key2, output, decrypted_output, password="redhat")
    verify_files(inputfile, decrypted_output)


def test_ks_sign_data():
    ks = jce.KeyStore("tests/files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed = ks.sign(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify(key, "hello", signed)


def test_ks_sign_data_fails():
    ks = jce.KeyStore("tests/files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed = ks.sign(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert not ks.verify(key, "hello2", signed)


def test_ks_sign_verify_file():
    inputfile = "tests/files/text.txt"
    tempdir = tempfile.TemporaryDirectory()
    shutil.copy(inputfile, tempdir.name)
    ks = jce.KeyStore("tests/files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    file_to_be_signed = os.path.join(tempdir.name, "text.txt")
    signed = ks.sign_file(key, file_to_be_signed, "redhat", write=True)
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify_file(key, file_to_be_signed, file_to_be_signed + ".asc")


def test_ks_creation_expiration_time():
    """
    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    tmpdir = tempfile.TemporaryDirectory()
    # First let us check from the file
    keypath = "tests/files/store/pgp_keys.asc"
    ks = jce.KeyStore(tmpdir.name)
    k = ks.import_cert(keypath)
    assert etime.date() == k.expirationtime.date()
    assert ctime.date() == k.creationtime.date()

    # now with a new key and creation time
    ctime = datetime.datetime(2010, 10, 10, 20, 53, 47)
    newk = ks.create_newkey("redhat", "Another test key", creation=ctime)
    assert ctime.date() == newk.creationtime.date()
    assert not newk.expirationtime

    # Now both creation and expirationtime
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2025, 12, 15, 20, 53, 47)
    newk = ks.create_newkey(
        "redhat", "Another test key", creation=ctime, expiration=etime
    )
    assert ctime.date() == newk.creationtime.date()
    assert etime.date() == newk.expirationtime.date()


def test_get_all_keys():
    ks = jce.KeyStore("./tests/files/store")
    keys = ks.get_all_keys()
    assert 3 == len(keys)
    # TODO: add more checks here in future


def test_get_pub_key():
    """Verifies that we export only the public key part from any key

    """
    ks = jce.KeyStore("./tests/files/store")
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key = ks.get_key(fingerprint)
    # verify that the key is a secret
    key.keytype == 1

    # now get the public key
    pub_key = key.get_pub_key()
    assert pub_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_same_key_import_error():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    ks.import_cert("tests/files/store/public.asc")
    with pytest.raises(jce.SameKeyError):
        ks.import_cert("tests/files/store/public.asc")
