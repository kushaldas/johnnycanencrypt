import os
import johnnycanencrypt as jce

DATA= "Kushal loves 🦀"

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
    assert original_text ==  decrypted_text

def test_encryption_of_multiple_keys():
    "Encrypt bytes to a file using multiple keys"
    output = "/tmp/multiple-enc.asc"
    if os.path.exists(output):
        os.remove(output)
    jce.encrypt_bytes_to_file(["tests/files/public.asc", "tests/files/hellopublic.asc"], DATA.encode("utf-8"), output.encode("utf-8"), armor=True)
    assert os.path.exists(output)
    # Now let us decrypt it via first secret key
    with open(output, "rb") as f:
        enc = f.read()
    jp = jce.Johnny("tests/files/hellosecret.asc")
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")

    jp = jce.Johnny("tests/files/secret.asc")
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")


def test_encrypt_decrypt_bytes():
    "Tests raw bytes as output"
    j = jce.Johnny("tests/files/public.asc")
    enc = j.encrypt_bytes(DATA.encode("utf-8"))
    jp = jce.Johnny("tests/files/secret.asc")
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")

def test_encrypt_decrypt_bytes_armored():
    "Tests ascii-armored output"
    j = jce.Johnny("tests/files/public.asc")
    enc = j.encrypt_bytes(DATA.encode("utf-8"), armor=True)
    assert enc.startswith(b"-----BEGIN PGP MESSAGE-----")
    jp = jce.Johnny("tests/files/secret.asc")
    result = jp.decrypt_bytes(enc, "redhat")
    assert DATA == result.decode("utf-8")



def test_encrypt_decrypt_files():
    "Tests encrypt/decrypt file in binary format"
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)

    # Now encrypt and then decrypt
    j = jce.Johnny("tests/files/public.asc")
    assert j.encrypt_file(inputfile.encode("utf-8"), output.encode("utf-8"))
    jp = jce.Johnny("tests/files/secret.asc")
    assert jp.decrypt_file(output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat")

    verify_files(inputfile, decrypted_output)

def test_encrypt_decrypt_files_armored():
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.asc"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)

    # Now encrypt and then decrypt
    j = jce.Johnny("tests/files/public.asc")
    assert j.encrypt_file(inputfile.encode("utf-8"), output.encode("utf-8"), armor=True)
    jp = jce.Johnny("tests/files/secret.asc")
    assert jp.decrypt_file(output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat")

    with open(output) as f:
        line = f.readline().strip("\n")
        assert line == "-----BEGIN PGP MESSAGE-----"

    verify_files(inputfile, decrypted_output)
