# Changlelog

## [Unreleased]

- If the public/secret key file is missing, while trying to create a `Johnny` object will raise `FileNotFound` error.
- If one tries to decrypt using a public key file, it will throw `AttributeError`.
- `encrypt_bytes` now returns bytes (instead of string).
- `encrypt_bytes` takes a third argument, `armor` as boolean, to return ascii-armored bytes or not.
- `encrypt_file` takes a third argument, `armor` as boolean, writes the output file ascii armored if true.

## [0.1.0] - 2020-07-11

- Initial release

