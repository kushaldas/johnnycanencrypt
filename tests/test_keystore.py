import datetime
import os
import shutil
import tempfile
import sqlite3

import pytest
import vcr
from pprint import pprint

import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

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


def test_create_primary_key_with_encryption():
    ks = jce.KeyStore(tmpdirname.name)
    newkey = ks.create_key(
        "redhat",
        "test key42 <42@example.com>",
        jce.Cipher.RSA4k,
        whichkeys=1,
        can_primary_sign=True,
    )
    assert newkey.can_primary_sign == True


def test_keystore_lifecycle():
    # Before anything let us first delete if any existing db
    pathname = os.path.join(tmpdirname.name, "jce.db")
    if os.path.exists(pathname):
        os.remove(pathname)
    # Now create a fresh db
    ks = jce.KeyStore(tmpdirname.name)
    newkey = ks.create_key("redhat", "test key1 <email@example.com>", jce.Cipher.RSA4k)
    # the default key must be of secret
    assert newkey.keytype == jce.KeyType.SECRET

    ks.import_key("tests/files/store/public.asc")
    ks.import_key("tests/files/store/pgp_keys.asc")
    ks.import_key("tests/files/store/hellopublic.asc")
    ks.import_key("tests/files/store/secret.asc")
    # Now check the numbers of keys in the store
    assert (2, 2) == ks.details()

    ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert (2, 1) == ks.details()

    # Now verify email cache
    key_via_fingerprint = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys_via_emails = ks.get_keys(qvalue="kushaldas@gmail.com", qtype="email")
    assert len(keys_via_emails) == 1
    assert key_via_fingerprint == keys_via_emails[0]

    # Also verify that kushal's primary key can sign
    assert key_via_fingerprint.can_primary_sign == True

    # Now verify name cache
    key_via_fingerprint = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    keys_via_names = ks.get_keys(
        qvalue="Test User2 <random@example.com>", qtype="value"
    )
    assert len(keys_via_names) == 1
    assert key_via_fingerprint == keys_via_names[0]


def test_keystore_contains_key():
    "verifies __contains__ method for keystore"
    ks = jce.KeyStore(tmpdirname.name)
    keypath = "tests/files/store/secret.asc"
    k = ks.import_key(keypath)
    _, fingerprint, keytype, exp, ctime, othervalues = jce.parse_cert_file(keypath)

    # First only the fingerprint
    assert fingerprint in ks
    # Next the Key object
    assert k in ks
    # This should be false
    assert not "1111111" in ks


def test_keystore_details():
    ks = jce.KeyStore("./tests/files/store")
    assert (1, 2) == ks.details()


def test_keystore_keyids():
    ks = jce.KeyStore("./tests/files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert key.keyid == "D8219C8C43F6C5E1"


def test_keystore_get_via_keyids():
    ks = jce.KeyStore("./tests/files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys = ks.get_keys_by_keyid("FB82AA5D326DA75D")
    assert len(keys) == 1
    assert key == keys[0]


def test_keystore_key_uids():
    ks = jce.KeyStore("./tests/files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert "kushal@fedoraproject.org" == key.uids[0]["email"]
    assert "mail@kushaldas.in" == key.uids[-1]["email"]


def test_key_password_change():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    k = ks.import_key("tests/files/store/secret.asc")
    k2 = ks.update_password(k, "redhat", "byebye")
    data = ks.sign_detached(k2, b"hello", "byebye")


def test_key_deletion():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    ks.import_key("tests/files/store/public.asc")
    k = ks.import_key("tests/files/store/pgp_keys.asc")
    ks.import_key("tests/files/store/hellopublic.asc")
    ks.import_key("tests/files/store/hellosecret.asc")
    ks.import_key("tests/files/store/secret.asc")
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


def test_ks_update_expiry_time_for_subkeys():
    "Updates expiry time for a given subkey"
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    ks.import_key("tests/files/store/hellosecret.asc")
    ks.import_key("tests/files/store/secret.asc")

    key = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    subkeys = [
        "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F",
    ]
    newexpiration = datetime.datetime(2050, 10, 25, 10)
    newkey = ks.update_expiry_in_subkeys(key, subkeys, newexpiration, "redhat")
    for _, skey in newkey.othervalues["subkeys"].items():
        if skey[0] == "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F":
            date = skey[1]
            assert date.date() == datetime.date(2050, 10, 25)

    with pytest.raises(ValueError):
        newkey = ks.update_expiry_in_subkeys(key, subkeys, None, "redhat")


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


def test_ks_encrypt_decrypt_filehandler(encrypt_decrypt_file):
    "Encrypts and decrypt some bytes"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"

    ks = jce.KeyStore("tests/files/store")
    public_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(inputfile, "rb") as fobj:
        assert ks.encrypt_file(public_key, fobj, output)
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(output, "rb") as fobj:
        ks.decrypt_file(secret_key, fobj, decrypted_output, password="redhat")
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
    signed = ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify(key, "hello", signed)


def test_ks_sign_data_fails():
    ks = jce.KeyStore("tests/files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed = ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert not ks.verify(key, "hello2", signed)


def test_ks_sign_verify_file_detached():
    inputfile = "tests/files/text.txt"
    tempdir = tempfile.TemporaryDirectory()
    shutil.copy(inputfile, tempdir.name)
    ks = jce.KeyStore("tests/files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    file_to_be_signed = os.path.join(tempdir.name, "text.txt")
    signed = ks.sign_file_detached(key, file_to_be_signed, "redhat", write=True)
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify_file_detached(key, file_to_be_signed, file_to_be_signed + ".asc")


def test_ks_userid_signing():
    pathname = os.path.join(tmpdirname.name, "jce.db")
    if os.path.exists(pathname):
        os.remove(pathname)
    # Now create a fresh db
    ks = jce.KeyStore(tmpdirname.name)
    k = ks.import_key("tests/files/store/pgp_keys.asc")
    t2 = ks.import_key("tests/files/store/secret.asc")

    # now let us sign the keys in kushal's uids
    k = ks.certify_key(
        t2,
        k,
        ["Kushal Das <kushaldas@gmail.com>", "Kushal Das <kushal@fedoraproject.org>"],
        jce.SignatureType.PersonaCertification,
        password="redhat".encode("utf-8"),
    )
    # k now contains the new updated key
    for uid in k.uids:
        if (
            uid["value"] == "Kushal Das <kushaldas@gmail.com>"
            or uid["value"] == "Kushal Das <kushal@fedoraproject.org>"
        ):
            certs = uid["certifications"]
            # Only the new certification
            assert len(certs) == 1
            cert = certs[0]
            assert cert["certification_type"] == "persona"
            for data in cert["certification_list"]:
                if data[0] == "fingerprint":
                    assert data[1] == "F4F388BBB194925AE301F844C52B42177857DD79"
                if data[0] == "keyid":
                    assert data[1] == "C52B42177857DD79"
        else:
            assert len(uid["certifications"]) == 0


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
    k = ks.import_key(keypath)
    assert etime.date() == k.expirationtime.date()
    assert ctime.date() == k.creationtime.date()

    # now with a new key and creation time
    ctime = datetime.datetime(2010, 10, 10, 20, 53, 47)
    newk = ks.create_key(
        "redhat", "Another test key", ciphersuite=jce.Cipher.Cv25519, creation=ctime
    )
    assert ctime.date() == newk.creationtime.date()
    assert not newk.expirationtime

    # Now both creation and expirationtime
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2025, 12, 15, 20, 53, 47)
    newk = ks.create_key("redhat", "Another test key", creation=ctime, expiration=etime)
    assert ctime.date() == newk.creationtime.date()
    assert etime.date() == newk.expirationtime.date()

    # Now both creation and expirationtime for subkeys
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2029, 12, 15, 20, 53, 47)
    newk = ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        creation=ctime,
        expiration=etime,
        subkeys_expiration=True,
    )
    assert ctime.date() == newk.creationtime.date()
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()

    # Now only providing expirationtime for subkeys
    etime = datetime.datetime(2030, 6, 5, 20, 53, 47)
    newk = ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        expiration=etime,
        subkeys_expiration=True,
    )
    assert datetime.datetime.now().date() == newk.creationtime.date()
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()


def test_get_all_keys():
    ks = jce.KeyStore("./tests/files/store")
    keys = ks.get_all_keys()
    assert 3 == len(keys)
    # TODO: add more checks here in future


def test_get_pub_key():
    """Verifies that we export only the public key part from any key"""
    ks = jce.KeyStore("./tests/files/store")
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key = ks.get_key(fingerprint)
    # verify that the key is a secret
    key.keytype == 1

    # now get the public key
    pub_key = key.get_pub_key()
    assert pub_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_add_userid():
    """Verifies that we can add uid to a cert"""
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    key = ks.import_key("tests/files/store/secret.asc")
    # check that there is only one userid
    assert len(key.uids) == 1

    # now add a new userid
    key2 = ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")

    assert key2.fingerprint == key.fingerprint
    assert len(key2.uids) == 2
    assert key2.keytype == jce.KeyType.SECRET


def test_add_and_revoke_userid():
    """Verifies that we can add uid to a cert"""
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    key = ks.import_key("tests/files/store/secret.asc")
    # check that there is only one userid
    assert len(key.uids) == 1

    # now add a new userid
    key2 = ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")

    assert key2.fingerprint == key.fingerprint
    assert len(key2.uids) == 2
    assert key2.keytype == jce.KeyType.SECRET
    # because at first all user ids are valid
    for uid in key2.uids:
        assert uid["revoked"] == False

    # now let us reove the new user id
    key3 = ks.revoke_userid(key2, "Off Spinner <spin@example.com>", "redhat")
    # verify the values
    assert key3.fingerprint == key.fingerprint
    assert len(key3.uids) == 2
    assert key3.keytype == jce.KeyType.SECRET
    for uid in key3.uids:
        if uid["value"] == "Off Spinner <spin@example.com>":
            assert uid["revoked"] == True
        else:
            assert uid["revoked"] == False


def test_add_userid_fails_for_public():
    """Verifies that adding uid to a public key fails"""
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    key = ks.import_key("tests/files/store/public.asc")
    # verify that the key is a secret
    assert len(key.uids) == 1

    # now add a new userid
    with pytest.raises(ValueError):
        key2 = ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")


def test_update_subkey_expiry_time():
    "Updates the expirytime for a given subkey"
    ks = jce.KeyStore("tests/files/store")
    key = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    fps = [
        "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F",
    ]
    newkeyvalue = rjce.update_subkeys_expiry_in_cert(
        key.keyvalue, fps, 60 * 60 * 24, "redhat"
    )
    _, _, _, _, _, othervalues = rjce.parse_cert_bytes(newkeyvalue)
    tomorrow = datetime.date.today() + datetime.timedelta(days=1)
    for skey in othervalues["subkeys"]:
        if skey[1] == "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F":
            date = skey[3]
            assert date.date() == tomorrow


def test_same_key_import_error():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    ks.import_key("tests/files/store/public.asc")
    with pytest.raises(jce.CryptoError):
        ks.import_key("tests/files/store/public.asc")


def test_key_without_uid():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    k = ks.create_key("redhat")
    uids, fp, secret, et, ct, othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 0


def test_key_with_multiple_uids():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    uids = [
        "Kushal Das <kushaldas@gmail.com>",
        "kushal@freedom.press",
        "This is also Kushal",
    ]
    k = ks.create_key("redhat", uids)
    uids, fp, secret, et, ct, othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 3


def test_ks_upgrade():
    "tests db upgrade from an old db"
    tempdir = tempfile.TemporaryDirectory()
    shutil.copy("tests/files/store/oldjce.db", os.path.join(tempdir.name, "jce.db"))
    ks = jce.KeyStore(tempdir.name)
    con = sqlite3.connect(ks.dbpath)
    con.row_factory = sqlite3.Row
    # First we will check if this db schema is old or not
    with con:
        cursor = con.cursor()
        sql = "SELECT * from dbupgrade"
        cursor.execute(sql)
        fromdb = cursor.fetchone()
        assert fromdb["upgradedate"] == jce.DB_UPGRADE_DATE
    # TODO: Now verify the keys inside of the new db, in full.


def test_ks_upgrade_failure():
    "tests db upgrade failure from an old db because of existing file"
    tempdir = tempfile.TemporaryDirectory()
    shutil.copy("tests/files/store/oldjce.db", os.path.join(tempdir.name, "jce.db"))
    shutil.copy(
        "tests/files/store/oldjce.db", os.path.join(tempdir.name, "jce_upgrade.db")
    )
    with pytest.raises(RuntimeError):
        ks = jce.KeyStore(tempdir.name)


def test_get_encrypted_for():
    ks = jce.KeyStore("tests/files/store/")
    keyids = rjce.file_encrypted_for("tests/files/double_recipient.asc")
    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]
    with open("tests/files/double_recipient.asc", "rb") as fobj:
        data = fobj.read()
    keyids = rjce.bytes_encrypted_for(data)
    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]


@vcr.use_cassette("tests/files/test_fetch_key_by_fingerprint.yml")
def test_fetch_key_by_fingerprint():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    key = ks.fetch_key_by_fingerprint("EF6E286DDA85EA2A4BA7DE684E2C6E8793298290")
    assert len(key.uids) == 1
    uid = key.uids[0]
    assert uid["email"] == "torbrowser@torproject.org"
    assert uid["name"] == "Tor Browser Developers"


@vcr.use_cassette("tests/files/test_fetch_nonexistingkey_by_fingerprint.yml")
def test_fetch_nonexistingkey_by_fingerprint():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    with pytest.raises(jce.KeyNotFoundError):
        key = ks.fetch_key_by_fingerprint("EF6E286DDA85EA2A4BA7DE684E2C6E8793298291")


@vcr.use_cassette("tests/files/test_fetch_key_by_email.yml")
def test_fetch_key_by_email():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    key = ks.fetch_key_by_email("anwesha.srkr@gmail.com")
    assert len(key.uids) == 2
    uid = key.uids[0]
    assert uid["name"] == "Anwesha Das"
    assert key.fingerprint == "2871635BE3B4E5C04F02B848C353BFE051D06C33"


@vcr.use_cassette("tests/files/test_fetch_nonexistingkey_by_email.yml")
def test_fetch_nonexistingkey_by_email():
    tempdir = tempfile.TemporaryDirectory()
    ks = jce.KeyStore(tempdir.name)
    with pytest.raises(jce.KeyNotFoundError):
        ks.fetch_key_by_email("doesnotexists@kushaldas.in")
