# Changelog

## [unreleased]

## [0.13.1] - 2023-03-24

### Fixed

- Fixed #132 available_subkeys() method.

### Added

- Updated PyO3 dependency to 0.18.1.

## [0.13.0] - 2023-01-21

### Added

- We can now disable OTP for both YubiKey4/5 #130.

## [0.12.0] - 2023-01-12

### Added

- Adds `enable_otp_usb` in rjce.
- Adds `disable_otp_usb` in rjce.
- Changed license to LGPL-3.0-or-later

## [0.11.1] - 2022-12-05

### Added

- Trying to fix the wheels for Mac.

## [0.11.0] - 2022-11-09

### Added

- Type annotation for the rust part of the codebase.
- `can_primary_expire` new argument to `create_key` function call.
- Updated `pyo3` dependency to `0.17.2`.
- Adds `get_card_version` in rjce.
- Adds `TouchMode` enum in rjce.
- Adds `get_card_touch_policies` function to find available options.
- Adds `KeySlot` enum in rjce
- Adds `get_keyslot_touch_policy` function to set touch policy.
- Adds `set_keyslot_touch_policy` function to set touch policy.
- Updates pyo3 to `0.17.3`

## [0.10.0] - 2022-09-20

### Fixed

- Fixes #111 to verify compressed signed message.

### Added

- `verify_and_extract_bytes` function to extract the verified bytes.
- `verify_and_extract_file` function to extract the verified file.
- `get_ssh_pubkey` to get ssh style key for authentication subkey in rjce #114.
- Adds https://docs.rs/sshkeys/0.3.2/sshkeys/index.html as dependency.

## [0.9.0] - 2022-08-30

- Adds `setuptools-rust` as build system.
- Key.uids now contains the certification details of each user id.
- `merge_keys` in rjce now takes a force boolean argument.
- `certify_key` can sign/certify another key by both card and on disk primary key.

## [0.8.0] - 2022-08-18

### Added

- #96 `create_key` can now have signing capability for primary key.
- #97 `sync_smartcard` can identify if the primary key is on card.
- `upload_primary_to_smartcard` function in rjce.
- Renamed internal function `parse_and_move_a_subkey` to `parse_and_move_a_key`

## [0.7.0] - 2022-08-17

### Added

- `get_card_details` now also tells Pin retries left in the card.
- `sign_file_on_card` function in rjce.
- `sign_bytes_on_card` function in rjce.
- `verify_file` & `verify_file_detached` are two different functions in KeyStore (breaking change).
- `verify` takes optional detached signature to verify the given bytes.
- `sign_detached` will do detached signature, `sign` is for the other usecase.
- renamed `create_newkey` to `create_key` (breaking change).
- renamed `import_cert` to `import_key` (breaking change).
- Updates all dependencies.

### Fixed

- Now can fail gracefully with CryptoError exception in Python
- #80 also fails gracefully

## [0.6.0] - 2021-12-27

### Added

- `update_expiry_in_subkeys` method for the keystrore.
- `update_subkeys_expiry_in_cert` function in rjce.
- `revoke_userid` method for keystore.
- `add_userid` method for keystore.
- `update_password` method for keystore.
- ECDH decryption on smartcard for Curve25519 only.
- Adds `decrypt_file_on_card` function.
- Adds `decrypt_bytes_on_card` function.
- Upgrades dependencies, including pyo3 to 0.15.1 and sequoia-openpgp to 1.6.0.
- Adds `is_smartcard_connected` function in rjce.

### Fixed

- `get_key` method will return `None` in case no fingerprint is provided.
- Spelling mistake in API & docs about `expiary` -> `expiry`.

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

