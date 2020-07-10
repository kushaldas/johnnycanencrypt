# Johnny can encrypt

[![CircleCI branch](https://img.shields.io/circleci/project/github/kushaldas/johnnycanencrypt/master.svg)](https://circleci.com/gh/kushaldas/workflows/johnnycanencrypt/tree/master)

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

**NOTE** -- This is very much experimental code at the current state, please do not use it in production.

## How to build?

### Build dependencies in Fedora

```
sudo dnf install nettle clang clang-devel
```


```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install requirements-dev.txt
maturin develop
```

## Usage example

```Python
>>> import johnnycanencrypt as jce
>>> j = jce.Johnny("secret.asc")
>>> data = j.encrypt_bytes("kushal 🐍".encode("utf-8"))
>>> print(data)
-----BEGIN PGP MESSAGE-----

wcFMAwhsWpR1vDokAQ//UQGjrmmPLP0Td8pELf8XZEPh6fY9Xad6XHH6vQjGwvjG
36kK8ejRqyLbZpwVOO1FUfiZt6AyaeIEeEagoolMxmFl67mWBHsw5Z2NUPhydAwJ
EX+VdFn6CtRzQ0xG3T7rOCrsR50COO13gc4fIAn7Rxj1DyjqlFvur10FNnxRm0iJ
jnOwPnWVWKwoROzevfQd1Oef0n4nbkDUuyrS9oHSRFhFF/9I9bGtJhho0VIIcmFG
YVkhR0+QROTZ4edKotUg0R3UUfHmfwT0XcybGWMG/8Nh3W8pYuxwDdtbSMNDZzxu
o9TdpLrgoRIkhyGmuYWrURrRN1hmce5B6XOagWu7aKL7pFhP7Vd6LLoliDwY4G6x
1yKHbSo/1FEof7WBDujCksuVedUO8Gs9giitR/p/U9PBadeyiW0CKTYiTURkkNiF
g79lVfbmM54eZ9zmU+PraVNpekYXvH3o+lvXd5T39mo4Y/dv2fDCjo2aiZ/bE56Q
yn/0Hhmj2ikrsUk3NcuhO4zxt+VLctJt+lfk+R2hal+6NTaRkREdprPp4ltAt/bm
8xwBmqp+FDdxGgY+ItJkG69vsIf4WpPsvBI37fVbeYqrPsaz9NGlz2QKdfQvaH7j
R7rgxf24H2FjbbyNuHF3tJJa4Kfpnhq4nkxA/EdRP9JcVm/X568jLayTLyJGmrbS
PAHlVMLSBXQDApkY+5Veu3teRR5M2BLPr7X/gfeNnTlbZ4kF5S+E+0bjTjrz+6oo
dcsnTYxmcAm9hdPjng==
=1IYb
-----END PGP MESSAGE-----



>>> result = j.decrypt_bytes(data.encode("utf-8"), "mysecretpassword")
>>> print(result.decode("utf-8"))
kushal 🐍

```

## Quick API documentation

Remember that this will change a lot in the coming days.


```Python
import johnnycanencrypt as jce
```

To create new RSA4096 size key, call `jce.newkey("password", "userid")`, both *password* and *userid* are Python str.
Remember to save them into different files ending with *.asc*. 

To do any encryption/decryption we have to create an object of the **Johnny** class with the private or public key file.
Remember, except **password** input, every else takes `bytes` as input type.

### Signing a file with detached signature

```Python
j = Johnny("private.asc")
signature = j.sign_file_detached("filename.txt".encode("utf-8"), "password")
with open("filename.txt.asc", "w") as f:
    f.write(signature)
```

### Verifying a signature


```Python
j = Johnny("public.asc")
with open("filename.txt.asc") as f:
    sig = f.read()

verified = j.verify_file("filename.txt".encode("utf-8"), sig.encode("utf-8"))
print(f"Verified: {verified}")
```

For signing and verifying there are similar method available for bytes, `verify_bytes`, `sign_bytes_detached`.


### Encrypting and decrypting files

```Python
j = jce.Johnny("public.asc")
assert j.encrypt_file(inputfile.encode("utf-8"), output_file_path.encode("utf-8"))
jp = jce.Johnny("secret.asc")

result = jp.decrypt_file(output_file_path.encode("utf-8"), decrypted_output_path.encode("utf-8"), "password")
```



## LICENSE: GPLv3+
