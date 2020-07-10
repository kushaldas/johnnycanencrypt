import johnnycanencrypt as jce

DATA= "Kushal loves 🦀"

def test_sign():
    j = jce.Johnny("tests/files/secret.asc")
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    assert signature

def test_verify_bytes():
    j = jce.Johnny("tests/files/secret.asc")
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny("tests/files/public.asc")
    assert jp.verify_bytes(DATA.encode("utf-8"), signature.encode("utf-8"))


def test_verify_bytes_must_fail():
    j = jce.Johnny("tests/files/secret.asc")
    signature = j.sign_bytes_detached(DATA.encode("utf-8"), "redhat")
    jp = jce.Johnny("tests/files/public.asc")
    data2 = DATA + " "
    assert not jp.verify_bytes(data2.encode("utf-8"), signature.encode("utf-8"))


