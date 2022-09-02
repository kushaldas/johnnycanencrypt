import datetime

import johnnycanencrypt.johnnycanencrypt as rustjce

from tests.conftest import BASE_TESTSDIR


def test_parse_cert_file():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = BASE_TESTSDIR / "files/store/pgp_keys.asc"
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(keypath.as_posix())
    assert etime.date() == expirationtime.date()
    assert ctime.date() == creationtime.date()
    assert othervalues["can_primary_sign"] == True


def test_parse_cert_bytes():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us read from the file
    keypath = BASE_TESTSDIR / "files/store/pgp_keys.asc"
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
    keypath = BASE_TESTSDIR / "files/store/pgp_keys.asc"
    with open(keypath, "rb") as fobj:
        data = fobj.read()

    keypath = BASE_TESTSDIR / "files/store/kushal_updated_key.asc"
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
    keypath = (BASE_TESTSDIR / "files/store/secret.asc").as_posix()
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
    keypath = (BASE_TESTSDIR / "files/store/kushal_updated_key.asc").as_posix()
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
