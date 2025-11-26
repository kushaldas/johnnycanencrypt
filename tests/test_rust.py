# We will slowly add more tests for rust codebase
import datetime
import os
import tempfile

from conftest import BASE_TESTSDIR

import johnnycanencrypt as jce
from johnnycanencrypt import johnnycanencrypt as rjce


def test_update_primary_expiry_in_cert(tmp_path):
    ctime = datetime.datetime(2025, 1, 22, 21, 25, 25)
    etime = datetime.datetime(2026, 1, 22, 21, 25, 25)
    # First let us check from the file
    keypath = (
        BASE_TESTSDIR
        / "files"
        / "store"
        / "363F0180891AB46098F4463864AB0060FAB80A18.sec"
    )
    (
        _,
        _,
        _,
        expirationtime,
        creationtime,
        othervalues,
    ) = rjce.parse_cert_file(str(keypath))
    with open(keypath, "rb") as fobj:
        oldkeydata = fobj.read()
    assert etime.date() == expirationtime.date()
    assert ctime.date() == creationtime.date()
    assert othervalues["can_primary_sign"] == True
    newexpiration = datetime.datetime(2050, 10, 25, 10)
    now = datetime.datetime.now()
    # We need to send in the difference between expiration time and now
    etime = int(newexpiration.timestamp() - now.timestamp())
    newkeydata = rjce.update_primary_expiry_in_cert(oldkeydata, etime, "redhat")
    (
        _,
        _,
        _,
        expirationtime,
        creationtime,
        othervalues,
    ) = rjce.parse_cert_bytes(newkeydata)
    assert ctime.date() == creationtime.date()
    assert newexpiration.date() == expirationtime.date()
