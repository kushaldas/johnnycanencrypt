import os
import johnnycanencrypt as jce

DATA= "Kushal loves 🦀"

def test_encrypt_decrypt_bytes():
    j = jce.Johnny("tests/files/public.asc")
    enc = j.encrypt_bytes(DATA.encode("utf-8"))
    jp = jce.Johnny("tests/files/secret.asc")
    result = jp.decrypt_bytes(enc.encode("utf-8"), "redhat")
    assert DATA == result.decode("utf-8")

def test_encrypt_decrypt_files():
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    # Remove any existing test files
    if os.path.exists(output):
        os.remove(output)
    if os.path.exists(decrypted_output):
        os.remove(decrypted_output)

    # Now encrypt and then decrypt
    j = jce.Johnny("tests/files/public.asc")
    assert j.encrypt_file(inputfile.encode("utf-8"), output.encode("utf-8"))
    jp = jce.Johnny("tests/files/secret.asc")
    result = jp.decrypt_file(output.encode("utf-8"), decrypted_output.encode("utf-8"), "redhat")
    # read both the files
    with open(inputfile) as f:
        original_text = f.read()

    with open(decrypted_output) as f:
        decrypted_text = f.read()

    assert original_text ==  decrypted_text

