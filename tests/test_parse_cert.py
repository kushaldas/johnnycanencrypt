import johnnycanencrypt.johnnycanencrypt as rustjce
import datetime


def test_parse_cert_file():
    """Tests the rust implementation of the pgp key.

    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime= datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = "tests/files/store/pgp_keys.asc"
    uids, fingerprint, keytype, expirationtime, creationtime = rustjce.parse_cert_file(keypath)
    assert etime == expirationtime
    assert ctime == creationtime


