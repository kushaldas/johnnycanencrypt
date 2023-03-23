import datetime
import shutil
import sqlite3

import pytest
import vcr

import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

from .conftest import BASE_TESTSDIR
from .utils import verify_files

DATA = "Kushal loves 🦀"


def test_correct_keystore_path():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")


def test_nonexisting_keystore_path():
    with pytest.raises(OSError):
        ks = jce.KeyStore(BASE_TESTSDIR / "files2/")


def test_str(tmp_path):
    ks = jce.KeyStore(tmp_path)
    assert str(ks) == f"<KeyStore dbpath={tmp_path.as_posix()}/jce.db>"


def test_no_such_key():
    with pytest.raises(jce.KeyNotFoundError):
        ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
        key = ks.get_key("A4F388BBB194925AE301F844C52B42177857DD79")


def test_create_primary_key_with_encryption(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    newkey = ks.create_key(
        "redhat",
        "test key42 <42@example.com>",
        jce.Cipher.RSA4k,
        whichkeys=1,
        can_primary_sign=True,
    )
    assert newkey.can_primary_sign == True


def test_keystore_lifecycle(tmp_path):
    # Now create a fresh db
    ks = jce.KeyStore(tmp_path.as_posix())
    newkey = ks.create_key("redhat", "test key1 <email@example.com>", jce.Cipher.RSA4k)
    # the default key must be of secret
    assert newkey.keytype == jce.KeyType.SECRET

    ks.import_key((BASE_TESTSDIR / "files/store/public.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/pgp_keys.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/hellopublic.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())
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


def test_keystore_contains_key(tmp_path):
    "verifies __contains__ method for keystore"
    ks = jce.KeyStore(tmp_path.as_posix())
    keypath = BASE_TESTSDIR / "files/store/secret.asc"
    k = ks.import_key(keypath.as_posix())
    _, fingerprint, keytype, exp, ctime, othervalues = jce.parse_cert_file(
        keypath.as_posix()
    )

    # First only the fingerprint
    assert fingerprint in ks
    # Next the Key object
    assert k in ks
    # This should be false
    assert not "1111111" in ks


def test_keystore_details():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    assert (1, 2) == ks.details()


def test_keystore_keyids():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert key.keyid == "D8219C8C43F6C5E1"


def test_keystore_get_via_keyids():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys = ks.get_keys_by_keyid("FB82AA5D326DA75D")
    assert len(keys) == 1
    assert key == keys[0]


def test_keystore_key_uids():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert "kushal@fedoraproject.org" == key.uids[0]["email"]
    assert "mail@kushaldas.in" == key.uids[-1]["email"]


def test_key_password_change(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    k = ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())
    k2 = ks.update_password(k, "redhat", "byebye")
    data = ks.sign_detached(k2, b"hello", "byebye")


def test_key_deletion(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/public.asc").as_posix())
    k = ks.import_key((BASE_TESTSDIR / "files/store/pgp_keys.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/hellopublic.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/hellosecret.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())
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
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert key.fingerprint == "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"


def test_ks_update_expiry_time_for_subkeys(tmp_path):
    "Updates expiry time for a given subkey"
    ks = jce.KeyStore(tmp_path.as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/hellosecret.asc").as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())

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
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
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
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
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


def test_ks_encrypt_decrypt_bytes_to_file(tmp_path):
    "Encrypts and decrypt some bytes"
    outputfile = tmp_path / "encrypted.asc"
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert ks.encrypt(secret_key, DATA, outputfile=outputfile.as_posix())
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_bytes_to_file_multiple_recipients(tmp_path):
    "Encrypts and decrypt some bytes"
    outputfile = tmp_path / "encrypted.asc"
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert ks.encrypt([key1, key2], DATA, outputfile=outputfile.as_posix())
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_text = ks.decrypt(secret_key, encrypted, password="redhat").decode(
        "utf-8"
    )
    assert DATA == decrypted_text


def test_ks_encrypt_decrypt_file(tmp_path):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files/text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    public_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert ks.encrypt_file(public_key, inputfile.as_posix(), output.as_posix())
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    ks.decrypt_file(
        secret_key, output.as_posix(), decrypted_output.as_posix(), password="redhat"
    )
    verify_files(inputfile, decrypted_output)


def test_ks_encrypt_decrypt_filehandler(tmp_path):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files/text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    public_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(inputfile, "rb") as fobj:
        assert ks.encrypt_file(public_key, fobj, output.as_posix())
    secret_key = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(output, "rb") as fobj:
        ks.decrypt_file(
            secret_key, fobj, decrypted_output.as_posix(), password="redhat"
        )
    verify_files(inputfile, decrypted_output)


def test_ks_encrypt_decrypt_file_multiple_recipients(tmp_path):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files/text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    encrypted = ks.encrypt_file([key1, key2], inputfile.as_posix(), output.as_posix())
    secret_key1 = ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    ks.decrypt_file(
        secret_key1, output.as_posix(), decrypted_output.as_posix(), password="redhat"
    )
    verify_files(inputfile, decrypted_output)
    secret_key2 = ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    ks.decrypt_file(
        secret_key2, output.as_posix(), decrypted_output.as_posix(), password="redhat"
    )
    verify_files(inputfile, decrypted_output)


def test_ks_sign_data():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed = ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify(key, "hello", signed)


def test_ks_sign_data_fails():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed = ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert not ks.verify(key, "hello2", signed)


def test_ks_sign_verify_file_detached(tmp_path):
    inputfile = BASE_TESTSDIR / "files/text.txt"
    shutil.copy(inputfile, tmp_path.as_posix())
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    file_to_be_signed = tmp_path / "text.txt"
    signed = ks.sign_file_detached(
        key, file_to_be_signed.as_posix(), "redhat", write=True
    )
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert ks.verify_file_detached(
        key, file_to_be_signed.as_posix(), file_to_be_signed.as_posix() + ".asc"
    )


def test_ks_userid_signing(tmp_path):
    # Now create a fresh db
    ks = jce.KeyStore(tmp_path.as_posix())
    k = ks.import_key((BASE_TESTSDIR / "files/store/pgp_keys.asc").as_posix())
    t2 = ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())

    # now let us sign the keys in kushal's uids
    k = ks.certify_key(
        t2,
        k,
        ["Kushal Das <kushaldas@gmail.com>", "Kushal Das <kushal@fedoraproject.org>"],
        jce.SignatureType.PersonaCertification,
        password="redhat",
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


def test_ks_creation_expiration_time(tmp_path):
    """
    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = BASE_TESTSDIR / "files/store/pgp_keys.asc"
    ks = jce.KeyStore(tmp_path.as_posix())
    k = ks.import_key(keypath.as_posix())
    assert etime.date() == k.expirationtime.date()
    assert ctime.date() == k.creationtime.date()

    # now with a new key and creation time
    ctime = datetime.datetime(2010, 10, 10, 20, 53, 47)
    newk = ks.create_key(
        "redhat", "Another test key", ciphersuite=jce.Cipher.Cv25519, creation=ctime
    )
    assert ctime.date() == newk.creationtime.date()
    assert not newk.expirationtime

    # Now both creation and expirationtime for primary key
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2025, 12, 15, 20, 53, 47)
    newk = ks.create_key(
        "redhat",
        "Another test key",
        creation=ctime,
        expiration=etime,
        can_primary_expire=True,
    )
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
    assert not newk.expirationtime
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()

    # Now verify both subkeys and primary can expire
    etime = datetime.datetime(2030, 6, 5, 20, 53, 47)
    newk = ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        expiration=etime,
        subkeys_expiration=True,
        can_primary_expire=True,
    )
    assert datetime.datetime.now().date() == newk.creationtime.date()
    assert etime.date() == newk.expirationtime.date()
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()


def test_get_all_keys():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    keys = ks.get_all_keys()
    assert 3 == len(keys)
    # TODO: add more checks here in future


def test_get_pub_key():
    """Verifies that we export only the public key part from any key"""
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key = ks.get_key(fingerprint)
    # verify that the key is a secret
    assert key.keytype == jce.KeyType.SECRET

    # now get the public key
    pub_key = key.get_pub_key()
    assert pub_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_add_userid(tmp_path):
    """Verifies that we can add uid to a cert"""
    ks = jce.KeyStore(tmp_path.as_posix())
    key = ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())
    # check that there is only one userid
    assert len(key.uids) == 1

    # now add a new userid
    key2 = ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")

    assert key2.fingerprint == key.fingerprint
    assert len(key2.uids) == 2
    assert key2.keytype == jce.KeyType.SECRET


def test_add_and_revoke_userid(tmp_path):
    """Verifies that we can add uid to a cert"""
    ks = jce.KeyStore(tmp_path.as_posix())
    key = ks.import_key((BASE_TESTSDIR / "files/store/secret.asc").as_posix())
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


def test_add_userid_fails_for_public(tmp_path):
    """Verifies that adding uid to a public key fails"""
    ks = jce.KeyStore(tmp_path.as_posix())
    key = ks.import_key((BASE_TESTSDIR / "files/store/public.asc").as_posix())
    # verify that the key is a secret
    assert len(key.uids) == 1

    # now add a new userid
    with pytest.raises(ValueError):
        key2 = ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")


def test_update_subkey_expiry_time():
    "Updates the expirytime for a given subkey"
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
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


def test_same_key_import_error(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/public.asc").as_posix())
    with pytest.raises(jce.CryptoError):
        ks.import_key((BASE_TESTSDIR / "files/store/public.asc").as_posix())


def test_key_without_uid(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    k = ks.create_key("redhat")
    uids, fp, secret, et, ct, othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 0


def test_key_with_multiple_uids(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    uids = [
        "Kushal Das <kushaldas@gmail.com>",
        "kushal@freedom.press",
        "This is also Kushal",
    ]
    k = ks.create_key("redhat", uids)
    uids, fp, secret, et, ct, othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 3


def test_ks_upgrade(tmp_path):
    "tests db upgrade from an old db"
    shutil.copy(BASE_TESTSDIR / "files/store/oldjce.db", tmp_path / "jce.db")

    ks = jce.KeyStore(tmp_path.as_posix())
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


def test_ks_upgrade_failure(tmp_path):
    "tests db upgrade failure from an old db because of existing file"
    shutil.copy(BASE_TESTSDIR / "files/store/oldjce.db", tmp_path / "jce.db")
    shutil.copy(BASE_TESTSDIR / "files/store/oldjce.db", tmp_path / "jce_upgrade.db")
    with pytest.raises(RuntimeError):
        ks = jce.KeyStore(tmp_path.as_posix())


def test_get_encrypted_for():
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store/")
    keyids = rjce.file_encrypted_for(
        (BASE_TESTSDIR / "files/double_recipient.asc").as_posix()
    )
    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]
    with open(BASE_TESTSDIR / "files/double_recipient.asc", "rb") as fobj:
        data = fobj.read()
    keyids = rjce.bytes_encrypted_for(data)
    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]


def test_available_subkeys_for_no_expiration():
    """Verifies that we export only the public key part from any key"""
    ks = jce.KeyStore(BASE_TESTSDIR / "files/store")
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key = ks.get_key(fingerprint)
    e, s, a = key.available_subkeys()
    assert e == True
    assert s == True
    assert a == False


def test_available_subkeys_for_expired(tmp_path):
    """Verifies that we export only the public key part from any key"""
    ks = jce.KeyStore(tmp_path.as_posix())
    ks.import_key((BASE_TESTSDIR / "files/store/pgp_keys.asc").as_posix())
    key = ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    e, s, a = key.available_subkeys()
    assert e == False
    assert s == False
    assert a == False


@vcr.use_cassette(
    (BASE_TESTSDIR / "files/test_fetch_key_by_fingerprint.yml").as_posix()
)
def test_fetch_key_by_fingerprint(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    key = ks.fetch_key_by_fingerprint("EF6E286DDA85EA2A4BA7DE684E2C6E8793298290")
    assert len(key.uids) == 1
    uid = key.uids[0]
    assert uid["email"] == "torbrowser@torproject.org"
    assert uid["name"] == "Tor Browser Developers"


@vcr.use_cassette(
    (BASE_TESTSDIR / "files/test_fetch_nonexistingkey_by_fingerprint.yml").as_posix()
)
def test_fetch_nonexistingkey_by_fingerprint(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    with pytest.raises(jce.KeyNotFoundError):
        key = ks.fetch_key_by_fingerprint("EF6E286DDA85EA2A4BA7DE684E2C6E8793298291")


@vcr.use_cassette((BASE_TESTSDIR / "files/test_fetch_key_by_email.yml").as_posix())
def test_fetch_key_by_email(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    key = ks.fetch_key_by_email("anwesha.srkr@gmail.com")
    assert len(key.uids) == 2
    uid = key.uids[0]
    assert uid["name"] == "Anwesha Das"
    assert key.fingerprint == "2871635BE3B4E5C04F02B848C353BFE051D06C33"


@vcr.use_cassette(
    (BASE_TESTSDIR / "files/test_fetch_nonexistingkey_by_email.yml").as_posix()
)
def test_fetch_nonexistingkey_by_email(tmp_path):
    ks = jce.KeyStore(tmp_path.as_posix())
    with pytest.raises(jce.KeyNotFoundError):
        ks.fetch_key_by_email("doesnotexists@kushaldas.in")
