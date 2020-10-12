import pytest

from .utils import clean_outputfiles


@pytest.fixture()
def encrypt_decrypt_file():
    inputfile = "tests/files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)
