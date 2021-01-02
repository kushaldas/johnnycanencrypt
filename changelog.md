# Changlelog

## [0.5.0] - 2021-01-03

### Added

- 
- `move_subkey_to_card` function to move all 3 subkeys to the card.
- We can also decrypt based on RSA keys on a smartcard.
- `sign_bytes_detached_on_card` and `sign_file_detached_on_card` to sign using smartcard.
- `set_name` to set the card holder's name in the card.
- `set_url` to set the URL to the public key of the card.
- `get_card_details` function in rjce to get smartcard details.
- `bytes_encrypted_for` and `file_encrypted_for` functions were added (these are costly function calls).
- `get_keys_by_keyid` to get keys for a given keyid
- `fetch_key_by_email` can fetch key from keys.openpgp.org for a given email id.
- `fetch_key_by_fingerprint` can fetch key from keys.openpgp.org for a given fingerprint.
- `encrypt_file` and `decrypt_file` can take an opened binary file handler in Python as input.

## [0.4.0] - 2020-11-01

### Added

- `create_newkey` can take multiple uids as string or None for no uid #40.

### Fixed

- #44 `pip install johnnycanencrypt` will now work

## [0.3.0] 2020-10-22

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

