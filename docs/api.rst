API Documentation
==================

For the rest of the documentation we assume that you imported the module as following.

::


        >>> import johnnycanencrypt as jce


.. function:: newkey(password, userid)

        Use the `newkey` function in the module to create a new keypair. It takes two arguments as str, a password, and userid.
        By default it creates the key with RSA4096, and returns a tuple of public,secret key as str. Raises `FileNotFound` error
        if the key file can not be accessed.

        ::

                >>> public, secret = jce.newkey("my super secret password using diceware", "test <test@example.com>")


        .. note:: Remember to save both the public and serect keys in a file to use in future.


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

        .. method:: verify_bytes(data: bytes, signature: bytes)

                Verifies if the signature is correct for the given data (as bytes). Returns `True` or `False`.

                ::

                        >>> j = jce.Johnny("tests/files/secret.asc")
                        >>> j.verify_bytes(encrypted_bytes, signature)