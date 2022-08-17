# Johnny can encrypt

[![CircleCI branch](https://img.shields.io/circleci/project/github/kushaldas/johnnycanencrypt/master.svg)](https://circleci.com/gh/kushaldas/workflows/johnnycanencrypt/tree/master)

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption, and detached signing operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

You can also use Yubikeys for the private key operations using this module.


## How to build?

First install [Rustup toolchain](https://rustup.rs) for your user.

### Build dependencies in Fedora

```
sudo dnf install nettle clang clang-devel nettle-devel python3-devel pcsc-lite-devel
```

### Build dependencies in Debian Buster

```
sudo apt install -y python3-dev libnettle6 nettle-dev libhogweed4 python3-pip python3-venv clang libpcsclite-dev
```

Finally build the module using `maturin`.

```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
maturin develop
```

For a release build use the following command.

```
maturin build --release
```

## Introduction

Please read the [Introduction](https://johnnycanencrypt.readthedocs.io/en/latest/introduction.html) documentation.

## API documentation

Please go through the [full API documentation](https://johnnycanencrypt.readthedocs.io/en/latest/api.html) for detailed descriptions.

## LICENSE: GPLv3+
