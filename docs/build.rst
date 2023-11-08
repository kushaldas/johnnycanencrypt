Installing for usage in a virtualenvironment
=============================================

Building this module requires Rust's nightly toolchain. You can install it following
the instructions from `rustup.rs <https://rustup.rs>`_.

You will need `libnettle` and `libnettle-dev` & `clang`, `libpcsclite1`, `libpcsclite-dev` (on Debian/Ubuntu) and `nettle` & `nettle-dev` `pcsc-lite-devel` & `clang` packages in Fedora.

::

        sudo apt install -y python3-dev libnettle8 nettle-dev libhogweed6 python3-pip python3-venv clang libpcsclite-dev libpcsclite1 libclang-9-dev

::

        sudo dnf install nettle clang clang-devel nettle-devel python3-devel pcsc-lite-devel 


Then you can just use `pip` module to install in your virtualenvironment.

::

        python -m pip install johnnycanencrypt


Building Johnny Can Encrypt for development
============================================


After you have the dependencies mentioned above, you can follow the steps below to build a wheel.

::

        python3 -m venv .venv
        source .venv/bin/activate
        python -m pip install -r requirements-dev.txt
        python setup.py develop

Only to build and test locally, you should execute

::

        python setup.py develop


To build a wheel use the following command.

::

        python setup.py bdist_wheel

How to run the tests?
----------------------

After you did the `python setup.py develop` as mentioned above, execute the following command.

::

        python -m pytest -vvv


How to run the smartcard related tests?
---------------------------------------

.. warning:: The following test will reset any Yubikey or smartcard connected to the system. Use it carefully.

All of these tests are right now kept as a Python script, and requires Yubikey series 5 hardware to test.

::

        python smartcardtests/smartcards.py

When asked, please make sure that only the test smartcard is conneccted to the system, and then type "Yes", without quotes.

