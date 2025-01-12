The internal johnnycanencrypt module written in Rust
====================================================

You will have to first import the module written in Rust.

::

        >>> from johnnycanencrypt import johnnycanencrypt as rjce

In most cases you don't have to use these, but if you have a reason, feel free to use them.

.. function:: parse_cert_bytes(certdata: bytes,nullpolicy: Optional[bool])) -> Tuple[List[Dict[Any, Any]], str, bool, datetime, datetime, Dict[Any, Any]]:

        This function parses the given bytes and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

        Return Tuple has the following:

        - The first item is a list of user ids as dictionary.
           [{"value": xxx, "comment": "xxx", "email": "xxx", "uri": "xxx", "revoked": boolean}, ]
        - Second item is the `fingerprint` as string.
        - Boolean  to mark if secret key or public
        - expirationtime as datetime.datetime
        - creationtime as datetime.datetime
        - othervalues is another dictionary, inside of it.
          - "subkeys": [("subkey keyid as hex", "fingerprint as hex", creationtime, expirationtime,
                       "keytype", "revoked as boolean")]. The subkey type can be of "encryption", "signing",
                       "authentication", or "unknown".
          - "keyid": "primary key id in hex"

        .. versionchanged:: 0.16.0
           `nullpolicy` argument was added.



.. function:: parse_cert_file(certfile: str,nullpolicy: Optional[bool]) -> Tuple[List[Dict[Any, Any]], str, bool, datetime, datetime, Dict[Any, Any]]:

        This function parses the given `certfile` path (as string) and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

        Return Tuple has the following:

        - The first item is a list of user ids as dictionary.
           [{"value": xxx, "comment": "xxx", "email": "xxx", "uri": "xxx", "revoked": boolean}, ]
        - Second item is the `fingerprint` as string.
        - Boolean  to mark if secret key or public
        - expirationtime as datetime.datetime
        - creationtime as datetime.datetime
        - othervalues is another dictionary, inside of it.
          - "subkeys": [("subkey keyid as hex", "fingerprint as hex", creationtime, expirationtime,
                       "keytype", "revoked as boolean")]. The subkey type can be of "encryption", "signing",
                       "authentication", or "unknown".
          - "keyid": "primary key id in hex"

        .. versionchanged:: 0.16.0
           `nullpolicy` argument was added.

.. function:: parse_keyring_file(certfile: str) -> List[...]:

        This function can parse any given keyring file. It always uses `nullpolicy` and returns a list of Tuples (as mentioned above).

        .. versionadded:: 0.16.0

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

.. function:: update_subkeys_expiry_in_cert(certdata: bytes, fingerprints: List[str], expirytime: int, password: string) -> bytes:

        This function updates the expiry date of the given subkeys and returns the new certificate.

.. function:: revoke_uid_in_cert(certdata: bytes, uid: bytes, password: string) -> bytes:

        Revokes the given UID in the key and returns the new key with the revoked UID.


.. function:: add_uid_in_cert(certdata: bytes, uid: bytes, password: string) -> bytes:

        Adds the given UID in the key and returns the new key.

.. function:: update_password(certdata: bytes, password: str, newpass: str) -> bytes:

        Updates the password of the key to a new password and then returns the updated key.


You can access the low level functions or `Johnny` class by the following way:

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
