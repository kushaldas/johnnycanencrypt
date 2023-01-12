# Johnny can encrypt

[![CircleCI branch](https://img.shields.io/circleci/project/github/kushaldas/johnnycanencrypt/main.svg)](https://circleci.com/gh/kushaldas/workflows/johnnycanencrypt/tree/main)

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption, and detached signing operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

You can also use Yubikeys for the private key operations using this module.

## How to build?

First install [Rustup toolchain](https://rustup.rs) for your user.

### Build dependencies in Fedora

```
sudo dnf install nettle clang clang-devel nettle-devel python3-devel pcsc-lite-devel
```

### Build dependencies in Debian Bullseye

```
sudo apt install -y python3-dev libnettle8 nettle-dev libhogweed6 python3-pip python3-venv clang libpcsclite-dev libpcsclite1 libclang-9-dev pkg-config

```


```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools
python -m pip install -r requirements-dev.txt
python setup.py develop
```

For a release build use the following command.

```
python setup.py bdist_wheel
```

## Introduction

Please read the [Introduction](https://johnnycanencrypt.readthedocs.io/en/latest/introduction.html) documentation.

## API documentation

Please go through the [full API documentation](https://johnnycanencrypt.readthedocs.io/en/latest/api.html) for detailed
descriptions.

## LICENSE: LGPL-3.0-or-later

