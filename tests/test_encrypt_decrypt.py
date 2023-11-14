import os

import johnnycanencrypt.johnnycanencrypt as jce

from .conftest import BASE_TESTSDIR
from .utils import _get_cert_data, verify_files

DATA = "Kushal loves 🦀"
HELLO_SECRET = BASE_TESTSDIR / "files" / "hellosecret.asc"
HELLO_PUBLIC = BASE_TESTSDIR / "files" / "hellopublic.asc"
PUBLIC_KEY = BASE_TESTSDIR / "files" / "public.asc"
SECRET_KEY = BASE_TESTSDIR / "files" / "secret.asc"


def test_encryption_of_multiple_keys_to_files(tmp_path):
    "Encrypt bytes to a file using multiple keys"
    output = tmp_path / "multiple-enc.asc"
    if os.path.exists(output):
        os.remove(output)
    certs = []
    for keyfilename in [
        PUBLIC_KEY,
        HELLO_PUBLIC,
    ]:
        certs.append(_get_cert_data(keyfilename))
    jce.encrypt_bytes_to_file(
        certs,
        DATA.encode("utf-8"),
        str(output).encode("utf-8"),
        armor=True,
    )
    assert os.path.exists(output)
    # Now let us decrypt it via first secret key
    with open(output, "rb") as f:
        enc = f.read()
    jp = jce.Johnny(_get_cert_data(HELLO_SECRET))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")

    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encryption_of_multiple_keys_of_a_file(tmp_path):
    "Encrypt bytes to a file using multiple keys"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"
    certs = []
    for keyfilename in [
        PUBLIC_KEY,
        HELLO_PUBLIC,
    ]:
        certs.append(_get_cert_data(keyfilename))

    jce.encrypt_file_internal(
        certs,
        str(inputfile).encode("utf-8"),
        str(output).encode("utf-8"),
        armor=True,
    )
    assert os.path.exists(output)
    # Now let us decrypt it via second secret key
    jp = jce.Johnny(_get_cert_data(HELLO_SECRET))
    assert jp.decrypt_file(
        str(output).encode("utf-8"), str(decrypted_output).encode("utf-8"), "redhat"
    )
    verify_files(inputfile, decrypted_output)

    # Now remove it for next step
    os.remove(decrypted_output)

    # Via first secret key
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    assert jp.decrypt_file(
        str(output).encode("utf-8"), str(decrypted_output).encode("utf-8"), "redhat"
    )
    verify_files(inputfile, decrypted_output)


def test_encryption_of_multiple_keys_to_bytes():
    "Encrypt bytes using multiple keys"
    certs = []
    for keyfilename in [
        PUBLIC_KEY,
        HELLO_PUBLIC,
    ]:
        certs.append(_get_cert_data(keyfilename))
    encrypted = jce.encrypt_bytes_to_bytes(
        certs,
        DATA.encode("utf-8"),
        armor=True,
    )
    # Now let us decrypt it via first secret key
    jp = jce.Johnny(_get_cert_data(HELLO_SECRET))
    result = jp.decrypt_bytes(encrypted, "redhat")
    assert DATA == result.decode("utf-8")

    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    result = jp.decrypt_bytes(encrypted, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_bytes():
    "Tests raw bytes as output"
    jp = jce.Johnny(_get_cert_data(PUBLIC_KEY))
    enc = jp.encrypt_bytes(DATA.encode("utf-8"))
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_bytes_armored():
    "Tests ascii-armored output"
    j = jce.Johnny(_get_cert_data(PUBLIC_KEY))
    enc = j.encrypt_bytes(DATA.encode("utf-8"), armor=True)
    assert enc.startswith(b"-----BEGIN PGP MESSAGE-----")
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_files(tmp_path):
    "Tests encrypt/decrypt file in binary format"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    # Now encrypt and then decrypt
    j = jce.Johnny(_get_cert_data(PUBLIC_KEY))
    assert j.encrypt_file(str(inputfile).encode("utf-8"), str(output).encode("utf-8"))
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    assert jp.decrypt_file(
        str(output).encode("utf-8"), str(decrypted_output).encode("utf-8"), "redhat"
    )

    verify_files(inputfile, decrypted_output)


def test_encrypt_decrypt_files_armored(tmp_path):
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.asc"
    decrypted_output = tmp_path / "text.txt"

    # Now encrypt and then decrypt
    j = jce.Johnny(_get_cert_data(PUBLIC_KEY))
    assert j.encrypt_file(
        str(inputfile).encode("utf-8"), str(output).encode("utf-8"), armor=True
    )
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    assert jp.decrypt_file(
        str(output).encode("utf-8"), str(decrypted_output).encode("utf-8"), "redhat"
    )

    with open(output) as f:
        line = f.readline().strip("\n")
        assert line == "-----BEGIN PGP MESSAGE-----"

    verify_files(inputfile, decrypted_output)


# The following data was generated while encrypting for 2 UID. Then we will try to decrypt
# using the second secret key.
# sequoia on  master [?] via 🦀 v1.46.0
# ❯ ./target/debug/sq encrypt -o double.asc --recipient-key-file ../rust/johnnycanencrypt/tests/files/store/hellopublic.asc --recipient-key-file ../rust/johnnycanencrypt/tests/files/store/public.asc msg.txt
# sequoia on  master [?] via 🦀 v1.46.0
# ❯ cp double.asc ../rust/johnnycanencrypt/tests/files/double_recipient.asc
# Test case for issue number #14
def test_decrypt_multiple_recipient_data():
    with open(BASE_TESTSDIR / "files" / "double_recipient.asc", "rb") as f:
        data = f.read()

    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    cleartext = jp.decrypt_bytes(data, "redhat")
    assert cleartext == b"Hello World! for 2.\n"


def test_encryption_of_multiple_keys_of_a_filehandler(tmp_path):
    "Encrypt bytes to an opened file using multiple keys"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted2.pgp"
    decrypted_output = tmp_path / "text2.txt"
    certs = []
    for keyfilename in [
        PUBLIC_KEY,
        HELLO_PUBLIC,
    ]:
        certs.append(_get_cert_data(keyfilename))

    with open(inputfile, "rb") as fobj:
        jce.encrypt_filehandler_to_file(
            certs,
            fobj,
            str(output).encode("utf-8"),
            armor=True,
        )
    assert os.path.exists(output)
    # Now let us decrypt it via second secret key
    jp = jce.Johnny(_get_cert_data(HELLO_SECRET))
    with open(output, "rb") as fobj:
        assert jp.decrypt_filehandler(
            fobj, str(decrypted_output).encode("utf-8"), "redhat"
        )
    verify_files(inputfile, decrypted_output)

    # Now remove it for next step
    os.remove(decrypted_output)

    # Via first secret key
    jp = jce.Johnny(_get_cert_data(SECRET_KEY))
    with open(output, "rb") as fobj:
        assert jp.decrypt_filehandler(
            fobj, str(decrypted_output).encode("utf-8"), "redhat"
        )
    verify_files(inputfile, decrypted_output)
