# Johnny can encrypt

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

**NOTE** -- This is very much experimental code at the current state, please do not use it in production.

## How to build?

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


## LICENSE: GPLv3+
