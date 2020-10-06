Building Johnny Can Encrypt
============================

Building this module requires Rust's nightly toolchain. You can install it following
the instructions from `rustup.rs <https://rustup.rs>`_.

You will need `libnettle` and `libnettle-dev` & `clang` (on Debian/Ubuntu) and `nettle` & `nettle-dev` & `clang` packages in Fedora.

Then you can follow the steps below to build a wheel.

::

        python3 -m venv .venv
        source .venv/bin/activate
        python3 -m pip install requirements-dev.txt
        maturin build

Only to build and test locally, you should execute

::

        maturin develop


To build a wheel use the following command.

::

        maturin build --manylinux=off

How to run the tests?
----------------------

After you did the `maturin develop` as mentioned above, execute the following command.

::

        python3 -m pytest -vvv

