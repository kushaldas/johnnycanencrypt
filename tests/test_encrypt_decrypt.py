import os

import johnnycanencrypt.johnnycanencrypt as jce

from .utils import _get_cert_data

DATA = "Kushal loves 🦀"


def clean_outputfiles(output, decrypted_output):
    # Remove any existing test files
    if os.path.exists(output):
        os.remove(output)
    if os.path.exists(decrypted_output):
        os.remove(decrypted_output)


def verify_files(inputfile, decrypted_output):
    # read both the files
    with open(inputfile) as f:
        original_text = f.read()

    with open(decrypted_output) as f:
        decrypted_text = f.read()
    assert original_text == decrypted_text


def test_encryption_of_multiple_keys_to_files():
    "Encrypt bytes to a file using multiple keys"
    output = "/tmp/multiple-enc.asc"
    if os.path.exists(output):
        os.remove(output)
    certs = []
    for keyfilename in ["tests/files/public.asc", "tests/files/hellopublic.asc"]:
        certs.append(_get_cert_data(keyfilename))
    jce.encrypt_bytes_to_file(
        certs,
        DATA.encode("utf-8"),
        output.encode("utf-8"),
        armor=True,
    )
    assert os.path.exists(output)
    # Now let us decrypt it via first secret key
    with open(output, "rb") as f:
        enc = f.read()
    jp = jce.Johnny(_get_cert_data("tests/files/hellosecret.asc"))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")

    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encryption_of_multiple_keys_of_a_file():
    "Encrypt bytes to a file using multiple keys"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)
    certs = []
    for keyfilename in ["tests/files/public.asc", "tests/files/hellopublic.asc"]:
        certs.append(_get_cert_data(keyfilename))

    jce.encrypt_file_internal(
        certs,
        inputfile.encode("utf-8"),
        output.encode("utf-8"),
        armor=True,
    )
    assert os.path.exists(output)
    # Now let us decrypt it via second secret key
    jp = jce.Johnny(_get_cert_data("tests/files/hellosecret.asc"))
    assert jp.decrypt_file(
        output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat"
    )
    verify_files(inputfile, decrypted_output)

    # Now remove it for next step
    os.remove(decrypted_output)

    # Via first secret key
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    assert jp.decrypt_file(
        output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat"
    )
    verify_files(inputfile, decrypted_output)


def test_encryption_of_multiple_keys_to_bytes():
    "Encrypt bytes using multiple keys"
    certs = []
    for keyfilename in ["tests/files/public.asc", "tests/files/hellopublic.asc"]:
        certs.append(_get_cert_data(keyfilename))
    encrypted = jce.encrypt_bytes_to_bytes(
        certs,
        DATA.encode("utf-8"),
        armor=True,
    )
    # Now let us decrypt it via first secret key
    jp = jce.Johnny(_get_cert_data("tests/files/hellosecret.asc"))
    result = jp.decrypt_bytes(encrypted, "redhat")
    assert DATA == result.decode("utf-8")

    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    result = jp.decrypt_bytes(encrypted, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_bytes():
    "Tests raw bytes as output"
    jp = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    enc = jp.encrypt_bytes(DATA.encode("utf-8"))
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_bytes_armored():
    "Tests ascii-armored output"
    j = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    enc = j.encrypt_bytes(DATA.encode("utf-8"), armor=True)
    assert enc.startswith(b"-----BEGIN PGP MESSAGE-----")
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_files():
    "Tests encrypt/decrypt file in binary format"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)

    # Now encrypt and then decrypt
    j = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert j.encrypt_file(inputfile.encode("utf-8"), output.encode("utf-8"))
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    assert jp.decrypt_file(
        output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat"
    )

    verify_files(inputfile, decrypted_output)


def test_encrypt_decrypt_files_armored():
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.asc"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)

    # Now encrypt and then decrypt
    j = jce.Johnny(_get_cert_data("tests/files/public.asc"))
    assert j.encrypt_file(inputfile.encode("utf-8"), output.encode("utf-8"), armor=True)
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    assert jp.decrypt_file(
        output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat"
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
    with open("tests/files/double_recipient.asc", "rb") as f:
        data = f.read()

    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    cleartext = jp.decrypt_bytes(data, "redhat")
    assert cleartext == b"Hello World! for 2.\n"


def test_encryption_of_multiple_keys_of_a_filehandler():
    "Encrypt bytes to an opened file using multiple keys"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted2.pgp"
    decrypted_output = "/tmp/text2.txt"
    clean_outputfiles(output, decrypted_output)
    certs = []
    for keyfilename in ["tests/files/public.asc", "tests/files/hellopublic.asc"]:
        certs.append(_get_cert_data(keyfilename))

    with open(inputfile, "rb") as fobj:
        jce.encrypt_filehandler_to_file(
            certs,
            fobj,
            output.encode("utf-8"),
            armor=True,
        )
    assert os.path.exists(output)
    # Now let us decrypt it via second secret key
    jp = jce.Johnny(_get_cert_data("tests/files/hellosecret.asc"))
    with open(output, "rb") as fobj:
        assert jp.decrypt_filehandler(fobj, decrypted_output.encode("utf-8"), "redhat")
    verify_files(inputfile, decrypted_output)

    # Now remove it for next step
    os.remove(decrypted_output)

    # Via first secret key
    jp = jce.Johnny(_get_cert_data("tests/files/secret.asc"))
    with open(output, "rb") as fobj:
        assert jp.decrypt_filehandler(fobj, decrypted_output.encode("utf-8"), "redhat")
    verify_files(inputfile, decrypted_output)
