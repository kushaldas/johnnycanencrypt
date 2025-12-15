def _get_cert_data(filepath):
    "Returns the filepath content as bytes"
    with open(filepath, "rb") as fobj:
        return fobj.read()


def verify_files(inputfile, decrypted_output):
    # read both the files
    with open(inputfile, "rb") as f:
        original_text = f.read()

    with open(decrypted_output, "rb") as f:
        decrypted_text = f.read()

    if original_text != decrypted_text:
        # Find first differing byte position
        for i, (a, b) in enumerate(zip(original_text, decrypted_text)):
            if a != b:
                assert False, (
                    f"File contents differ at byte {i}:\n"
                    f"  original: {original_text[max(0,i-5):i+5]!r}\n"
                    f"  decrypted: {decrypted_text[max(0,i-5):i+5]!r}"
                )
    assert len(original_text) == len(decrypted_text), \
        f"File sizes differ: original={len(original_text)} bytes, decrypted={len(decrypted_text)} bytes"

