The internal johnnycanencrypt module written in Rust
====================================================

You can access the low level functions or `Johnny` class by the following way:

::

        >>> from johnnycanencrypt import johnnycanencrypt as rjce

In most cases you don't have to use these, but if you have a reason, feel free to use them.

.. function:: encrypt_bytes_to_file(publickeys, data, output, armor=False)

        This function takes a list of public key file paths, and encrypts the given data in bytes to an output
        file. You can also pass boolen flag armor for armored output in the file.

        ::

                >>> rjce.encrypt_bytes_to_file(["tests/files/public.asc", "tests/files/hellopublic.asc"], b"Hello clear text", b"/tmp/encrypted_text.asc", armor=True)


        .. note:: Use this function if you have to encrypt for multiple recipents.

.. function:: get_ssh_pubkey(certdata, comment: Optional[str]) -> str:

        This function takes a public key and optional comment and then provides a string representing the authentication subkey to be used inside of SSH.


.. function:: enable_otp_usb() -> bool

        This function enables OTP application in the Yubikey.

.. function:: disable_otp_usb() -> bool

        This function disables OTP application in the Yubikey.

.. function:: get_key_cipher_details(certdata: bytes) -> List[tuple[str, str, int]]

        This function takes the key data as bytes, and returns a list of tuples containing (fingerprint, public key algorithm, bits size).

        ::

            >>> rjce.get_key_cipher_details(key.keyvalue)
            [('F4F388BBB194925AE301F844C52B42177857DD79', 'EdDSA', 256), ('102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F', 'EdDSA', 256), ('85B67F139D835FA56BA703DB5A7A1560D46ED4F6', 'ECDH', 256)]

.. function:: update_primary_expiry_on_card(certdata: bytes, expiry: int, pin: bytes) -> bytes:

        This function updates the expiry date using the Yubikey and public key as `certdata`. You will have to pass the expiry as `int` number of seconds (after which the key will expire).

        .. versionadded:: 0.15.0

.. function:: update_subkeys_expiry_on_card(certdata: bytes, fingerprints: List[str], expiry: int, pin: bytes) -> bytes:

        This function updates the expiry date of the given subkeys using Yubikey (the primary key must be on the Yubikey). You will have to pass the expiry as `int` number of seconds (after which the key will expire).

        .. versionadded:: 0.15.0

.. class:: Johnny(filepath)

        It creates an object of type `Johnny`, you can provide path to the either public key, or the private key based on the operation
        you want to do.

        .. method:: encrypt_bytes(data: bytes, armor=False)

                This method encrypts the given bytes and returns the encrypted bytes. If you pass `armor=True` to the method, then the
                returned value will be ascii armored bytes.

                ::

                            >>> j = jce.Johnny("tests/files/public.asc")
                            >>> enc = j.encrypt_bytes(b"mysecret", armor=True)


        .. method:: encrypt_file(inputfile: bytes, output: bytes, armor=False)

                This method encrypts the given inputfile and writes the raw encrypted bytes to the output path. If you pass `armor=True` to the method, then the
                output file will be written as ascii armored.

                ::

                            >>> j = jce.Johnny("tests/files/public.asc")
                            >>> enc = j.encrypt_file(b"blueleaks.tar.gz", b"notblueleaks.tar.gz.pgp", armor=True)


        .. method:: decrypt_bytes(data: bytes, password: str)

                Decrypts the given bytes based on the secret key and given password. If you try to decrypt while just using the public key,
                then it will raise `AttributeError`.

                ::

                        >>> jp = jce.Johnny("tests/files/secret.asc")
                        >>> result = jp.decrypt_bytes(enc, "redhat")


        .. method:: decrypt_file(inputfile: bytes, output: bytes, password: str)

                Decrypts the inputfile path  (in bytes) and wrties the decrypted data to the `output` file. Both the filepaths to be given as bytes.

                ::

                        >>> jp = jce.Johnny("tests/files/secret.asc")
                        >>> result = jp.decrypt_file(b"notblueleaks.tar.gz.pgp", "blueleaks.tar.gz", "redhat")


        .. method:: sign_bytes_detached(data: bytes, pasword: str)

                Signs the given bytes and returns the detached ascii armored signature as bytes.

                ::

                        >>> j = jce.Johnny("tests/files/secret.asc")
                        >>> signature = j.sign_bytes_detached(b"mysecret", "redhat")

                .. note:: Remember to save the signature somewhere on disk.

        .. method:: verify_bytes(data: bytes)

                Verifies if the signature is correct for the given signed data (as bytes). Returns `True` or `False`.

                ::

                        >>> j = jce.Johnny("tests/files/public.asc")
                        >>> j.verify_bytes(encrypted_bytes)

        .. method:: verify_and_extract_bytes(data: bytes)

                Verifies if the signature is correct for the given signed data (as bytes). Returns the actual message in Bytes.

                ::

                        >>> j = jce.Johnny("tests/files/public.asc")
                        >>> j.verify_and_extract_bytes(encrypted_bytes)


        .. method:: verify_bytes_detached(data: bytes, signature: bytes)

                Verifies if the signature is correct for the given data (as bytes). Returns `True` or `False`.

                ::

                        >>> j = jce.Johnny("tests/files/public.asc")
                        >>> j.verify_bytes(encrypted_bytes, signature)

        .. method:: verify_file(filepath: bytes)

                Verifies if the signature is correct for the given signed file (path as bytes). Returns `True` or `False`.

                ::

                        >>> j = jce.Johnny("tests/files/public.asc")
                        >>> j.verify_file(encrypted_bytes, signature)

        .. method:: verify_and_extract_file(filepath: bytes, output: bytes)

                Verifies and extracts the message from the signed file, return `True` in case of a success.


        .. method:: verify_file_detached(filepath: bytes, signature: bytes)

                Verifies if the signature is correct for the given signed file (path as bytes). Returns `True` or `False`.

                ::

                        >>> j = jce.Johnny("tests/files/public.asc")
                        >>> j.verify_file_detached(encrypted_bytes, signature)
