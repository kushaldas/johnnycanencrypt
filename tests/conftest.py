from pathlib import Path

import pytest

from .utils import clean_outputfiles

BASE_TESTSDIR = Path(__file__).parent


@pytest.fixture()
def encrypt_decrypt_file():
    inputfile = BASE_TESTSDIR / "files/text.txt"
    output = "/tmp/text-encrypted.pgp"
    decrypted_output = "/tmp/text.txt"
    clean_outputfiles(output, decrypted_output)
