import datetime
import os
import tempfile

import johnnycanencrypt.johnnycanencrypt as rustjce
from tests.conftest import BASE_TESTSDIR


def test_parse_keyring():
    """Tests parsing of a keyring file."""

    ringpath = BASE_TESTSDIR / "files" / "foo_keyring.asc"
    keys = rustjce.parse_keyring_file(str(ringpath))
    assert len(keys) == 2
    assert len(keys[0]) == 2  # The data and certdata


def test_write_to_keyring():
    """Tests writing to a keyring file."""

    ringpath = BASE_TESTSDIR / "files" / "foo_keyring.asc"
    keys = rustjce.parse_keyring_file(str(ringpath))
    assert len(keys) == 2
    certs = []
    for key in keys:
        certs.append(key[1])
    # Now write it in a temporary file
    with tempfile.TemporaryDirectory() as tmpdir:
        filename = os.path.join(tmpdir, "keyring.asc")
        rustjce.export_keyring_file(certs, filename)
        # Now the file has been written to disk
        # let us verify that the file exists.
        assert os.path.exists(filename) == True

        # Now re-read the keyring to verify that we have the right keys back
        newkeys = rustjce.parse_keyring_file(filename)
        assert len(newkeys) == 2


def test_parse_expired_old_cert():
    """Tests an old expried key.

    This will normally fail with StandardPolicy.
    """
    keypath = BASE_TESTSDIR / "files" / "store" / "old.asc"
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(str(keypath), nullpolicy=True)


def test_parse_cert_file():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's expired key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(str(keypath))
    assert etime.date() == expirationtime.date()
    assert ctime.date() == creationtime.date()
    assert othervalues["can_primary_sign"] == True


def test_parse_cert_bytes():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's expired key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us read from the file
    keypath = BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"
    with open(keypath, "rb") as fobj:
        data = fobj.read()

    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_bytes(data)
    assert etime.date() == expirationtime.date()
    assert ctime.date() == creationtime.date()


def test_merge_certs():
    """Tests the rust implementation of merging two OpenPGP keys.

    Tests via Kushal's old key, and the new key
    """
    # These two are known values from kushal
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us read from the file
    keypath = BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"
    with open(keypath, "rb") as fobj:
        data = fobj.read()

    keypath = BASE_TESTSDIR / "files" / "store" / "kushal_updated_key.asc"
    with open(keypath, "rb") as fobj:
        newdata = fobj.read()

    newcert = rustjce.merge_keys(data, newdata, False)
    assert isinstance(newcert, bytes)

    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        subkeys,
    ) = rustjce.parse_cert_bytes(newcert)

    assert ctime.date() == creationtime.date()
    assert not expirationtime


def test_no_primary_sign():
    keypath = str(BASE_TESTSDIR / "files" / "store" / "secret.asc")
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(keypath)
    assert othervalues["can_primary_sign"] == False


def test_uid_certs():
    "To test certifications on user ids"
    keypath = str(BASE_TESTSDIR / "files" / "store" / "kushal_updated_key.asc")
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(keypath)
    for uid in uids:
        if uid["value"] == "Kushal Das <kushaldas@gmail.com>":
            ctypes = {}
            assert len(uid["certifications"]) == 17
            for cert in uid["certifications"]:
                assert "creationtime" in cert
                assert "certification_type" in cert
                clist = cert["certification_list"]
                assert type(clist) == list
                for cvalue in clist:
                    if cvalue[0] == "fingerprint":
                        ctypes["fp"] = True
                    if cvalue[0] == "keyid":
                        ctypes["keyid"] = True
            # now verify that we have both the values in the certification_list
            assert ctypes["fp"]
            assert ctypes["keyid"]
