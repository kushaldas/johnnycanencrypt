The internal johnnycanencrypt module written in Rust
====================================================

You will have to first import the module written in Rust.

::

        >>> from johnnycanencrypt import johnnycanencrypt as rjce

In most cases you don't have to use these, but if you have a reason, feel free to use them.

For type annotation we have a Type Alias called `KeyData` as following:

::

        KeyData = Tuple[List[Dict[Any, Any]], str, bool, Optional[datetime], datetime, Dict[Any, Any]]

Which has the following structure.

The first item of the tuple is about `UID` and `certifications` for each UID., where each item is a dictionary, the following details:

::

         {'certifications': [{'certification_list': [('fingerprint',
                                               '93DA7006C2E7043E8C33ED1BA6C152738D03C7D1'),
                                              ('keyid', 'A6C152738D03C7D1')],
                       'certification_type': 'generic',
                       'creationtime': datetime.datetime(2021, 11, 3, 10, 54, 6)},
                      {'certification_list': [('fingerprint',
                                               '749596FAA93B58C88423141F198C1AFD505152DD'),
                                              ('keyid', '198C1AFD505152DD')],
                       'certification_type': 'generic',
                       'creationtime': datetime.datetime(2021, 11, 3, 10, 52, 50)}],
           'email': 'kushal@sunet.se',
           'name': 'Kushal Das',
           'revoked': False,
           'value': 'Kushal Das <kushal@sunet.se>'}

A list of certifications for the given UID, shows *email* and *name* and if
*revoked* or not, and the full *value* of the UID. Then fingerprint of the
primary key, and a *boolean* value to say if it secret key (`True`) or public
key (`False`). Next twovalues are *expirarion* and *creation* of the primary
key. *expiration* can be `None`.
The last time of the tuple is another dictionary, with keys explaining *can_primary_sign*, then *keyid* of the
primary key, and *subkeys* contains a list of tuples for each usable subkey. Each tuple in turn contains the following
`(subkey_id, fingerprint, creation, Optional[expriation])`


.. dropdown:: Experimental simpler API
    :open:
    :color: info

    .. function:: exp_parse_cert_bytes(certdata: bytes,nullpolicy: Optional[bool])) -> Dict[str, Any]:

        This function parses the given bytes and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

    .. function:: exp_parse_cert_file(certfile: str,nullpolicy: Optional[bool]) -> Dict[str, Any]:

        This function parses the given `certfile` path (as string) and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

    .. function:: exp_parse_keyring_file(certfile: str) -> List[Tuple[Dict[str, Any], bytes]]:

        This function can parse any given keyring file. It always uses `nullpolicy`, returns List of the following
        tuple of `KeyData` and certificate in bytes. In most cases you can discard the certificate data unless you
        want to access the indivitual certificate in future.

    Each of the above 3 functions provides dictioaries like below for each key.

    ::

        {'creation': datetime.datetime(2025, 1, 22, 22, 25, 25),
        'expiration': datetime.datetime(2026, 1, 22, 22, 25, 25),
        'fingerprint': '363F0180891AB46098F4463864AB0060FAB80A18',
        'othervalues': {'can_primary_sign': True,
                 'keyid': '64AB0060FAB80A18',
                 'subkeys': [{'creation': datetime.datetime(2025, 1, 22, 22, 25, 25),
                              'expiraton': datetime.datetime(2026, 1, 22, 22, 25, 25),
                              'fingerprint': '867555C6BD0F49A5FBC7EF0D1C29FABC7B9CFD3B',
                              'keyid': '1C29FABC7B9CFD3B',
                              'keytype': 'encryption',
                              'revoked': False},
                             {'creation': datetime.datetime(2025, 1, 22, 22, 25, 25),
                              'expiraton': datetime.datetime(2026, 1, 22, 22, 25, 25),
                              'fingerprint': '940B1446A0597D4F124A9DBEDDECF252395B4001',
                              'keyid': 'DDECF252395B4001',
                              'keytype': 'authentication',
                              'revoked': False}]},
        'secretkey': False,
        'uids': [{'certifications': [{'issuers': [('fingerprint',
                                                       '93DA7006C2E7043E8C33ED1BA6C152738D03C7D1'),
                                                      ('keyid',
                                                       'A6C152738D03C7D1')],
                               'type': 'generic',
                               'creation': datetime.datetime(2021, 11, 3, 10, 54, 6)}],
           'email': 'test@sunet.se',
           'name': 'Test Key',
           'revoked': False,
           'value': 'Test Key <test@sunet.se>'}]}


    .. versionadded:: 0.16.0

.. function:: parse_cert_bytes(certdata: bytes,nullpolicy: Optional[bool])) -> KeyData:

        This function parses the given bytes and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

        Returns `KeyData` type.

        .. versionchanged:: 0.16.0
           `nullpolicy` argument was added.


.. function:: parse_cert_file(certfile: str,nullpolicy: Optional[bool]) -> KeyData:

        This function parses the given `certfile` path (as string) and returns the parsed output as a Tuple. If you parse the `nullpolicy` argument, then we can parse old
        `sha1` based keys too.

        Returns `KeyData` type.

        .. versionchanged:: 0.16.0
           `nullpolicy` argument was added.

.. function:: update_primary_expiry_in_cert(certdata: bytes, expirytime: int, password: str ) -> bytes:

        Updates primary key expiry time in the certificate and returns the udpated certificate as bytes.

        .. versionadded:: 0.16.0


.. function:: update_subkeys_expiry_in_cert(certdata: bytes, fingerprints: List[str], expirytime: int, password: str ) -> bytes:

        Updates the expiry date of the given subkeys.


.. function:: parse_keyring_file(certfile: str) -> List[Tuple[KeyData, bytes]]:

        This function can parse any given keyring file. It always uses `nullpolicy`, returns List of the following
        tuple of `KeyData` and certificate in bytes. In most cases you can discard the certificate data unless you
        want to access the indivitual certificate in future.

        Tuple[KeyData, bytes]

        .. versionadded:: 0.16.0

.. function:: export_keyring_file(certs: List[bytes], keyringfilename: str) -> bool:

        This function exports a list of given certificates (public keys in bytes format) to a keyring file.

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


.. function:: revoke_uid_in_cert(certdata: bytes, uid: bytes, password: string) -> bytes:

        Revokes the given UID in the key and returns the new key with the revoked UID.


.. function:: add_uid_in_cert(certdata: bytes, uid: bytes, password: string) -> bytes:

        Adds the given UID in the key and returns the new key.

.. function:: update_password(certdata: bytes, password: str, newpass: str) -> bytes:

        Updates the password of the key to a new password and then returns the updated key.

.. function:: verify_userpin(pin: bytes) -> bool:

        Verifies the given `user` pin, returns True if right or False.

        .. versionadded:: 0.17.0

.. function:: verify_adminpin(pin: bytes) -> bool:

        Verifies the given `admin` pin, returns True if right or False.

        .. versionadded:: 0.17.0

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
