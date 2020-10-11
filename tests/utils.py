import os


def _get_cert_data(filepath):
    "Returns the filepath content as bytes"
    with open(filepath, "rb") as fobj:
        return fobj.read()


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
