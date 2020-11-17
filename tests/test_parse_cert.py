import datetime

import johnnycanencrypt.johnnycanencrypt as rustjce


def test_parse_cert_file():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = "tests/files/store/pgp_keys.asc"
    (
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ) = rustjce.parse_cert_file(keypath)
    assert etime.date() == expirationtime.date()
    assert ctime.date() == creationtime.date()


def test_parse_cert_bytes():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us read from the file
    keypath = "tests/files/store/pgp_keys.asc"
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
    keypath = "tests/files/store/pgp_keys.asc"
    with open(keypath, "rb") as fobj:
        data = fobj.read()

    keypath = "tests/files/store/kushal_updated_key.asc"
    with open(keypath, "rb") as fobj:
        newdata = fobj.read()

    newcert = rustjce.merge_keys(data, newdata)
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
