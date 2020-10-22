# Changlelog

## 2020-10-22

### Added

- `encrypt_bytes_to_file` can encrypt data for multiple recipients and saves to a file.
- Function signature to the `create_newkey` function.
- Uses sequoia-pgp 0.20.0 as dependency #31
- Can not use sha1 based keys with this library #29
- SQLite3 based KeyStore `jce.db`
- Python ENUMs key type and cipher type #33

### Fixed

- #14 decrypt when the data was encrypted for multiple recipients.
- Fixes documentation for `create_newkey` function name.

## [0.2.0] - 2020-07-15

### Added

- This changelog :)
- If the public/secret key file is missing, while trying to create a `Johnny` object will raise `FileNotFound` error.
- If one tries to decrypt using a public key file, it will throw `AttributeError`.
- `encrypt_bytes` now returns bytes (instead of string).
- `encrypt_bytes` takes a third argument, `armor` as boolean, to return ascii-armored bytes or not.
- `encrypt_file` takes a third argument, `armor` as boolean, writes the output file ascii armored if true.

## [0.1.0] - 2020-07-11

- Initial release

