# Johnny can encrypt

[![CircleCI branch](https://img.shields.io/circleci/project/github/kushaldas/johnnycanencrypt/master.svg)](https://circleci.com/gh/kushaldas/workflows/johnnycanencrypt/tree/master)

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

**NOTE** -- This is very much experimental code at the current state, please do not use it in production.

## How to build?

### Build dependencies in Fedora

```
sudo dnf install nettle clang clang-devel nettle-dev
```


```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install requirements-dev.txt
maturin develop
```

## Introduction

Please read the [Introduction](https://johnnycanencrypt.readthedocs.io/en/latest/introduction.html) documentation.

## API documentation

Please go through the [full API documentation](https://johnnycanencrypt.readthedocs.io/en/latest/api.html) for detailed descriptions.

## LICENSE: GPLv3+
