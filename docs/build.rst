Installing for usage in a virtualenvironment
=============================================

Building this module requires Rust's nightly toolchain. You can install it following
the instructions from `rustup.rs <https://rustup.rs>`_.

You will need `libnettle` and `libnettle-dev` & `clang`, `libpcsclite1`, `libpcsclite-dev` (on Debian/Ubuntu) and `nettle` & `nettle-dev` `pcsc-lite-devel` & `clang` packages in Fedora.

::

        sudo apt install -y python3-dev libnettle6 nettle-dev libhogweed4 python3-pip python3-venv clang libpcsclite-dev libpcsclite1

::

        sudo dnf install nettle clang clang-devel nettle-devel python3-devel pcsc-lite-devel 


Then you can just use `pip` module to install in your virtualenvironment.

::

        python3 -m pip install johnnycanencrypt


Building Johnny Can Encrypt for development
============================================


After you have the dependencies mentioned above, you can follow the steps below to build a wheel.

::

        python3 -m venv .venv
        source .venv/bin/activate
        python3 -m pip install requirements-dev.txt
        maturin build --manylinux=off

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

