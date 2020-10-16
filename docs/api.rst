API Documentation
==================

For the rest of the documentation we assume that you imported the module as following.

::


        >>> import johnnycanencrypt as jce




.. class:: KeyStore(path: str) -> None:

        Returns a KeyStore object. This is the primary class of the module, and all high level usage is available via methods of this class.
        It takes a path to the directory where it stores/reads the keys. Please make sure that only the **user** has read/write capability
        to this path.

        The keys are represented inside the directory in the **jce.db** sqlite3 database

        If you can check for existance of any fingerprint (str) or `Key` object in the via `in` opertor.

        ::

                >>> ks = jce.KeyStore("/var/lib/myamazingapp")
                >>> "HEXFINGERPRINT" in ks


        .. method:: create_newkey(password: str, uid: str = "", ciphersuite: Cipher = Cipher.RSA4k, creation: Optional[datetime.datetime] = None, expiration: Optional[datetime.datetime] = None) -> Key:

                Returns the public part of the newly created `Key` in the store
                directory. You can mention ciphersuite :class:`Cipher`  as
                *Cipher.RSA2k* or *Cipher.RSA4k*, or *Cipher.Cv25519*, while
                *Cipher.RSA4k* is the default. You can also provide
                `datetime.datetime` objects for creation time and expiration
                time. By default it will use the current time as creation time,
                and keys don't expire.

                ::

                        >>> ks = jce.KeyStore("/var/lib/myamazingapp")
                        >>> newkey = ks.create_newkey("supersecretpassphrasefromdiceware", "test key1 <email@example.com>", jce.KeyType.RSA4k)

        .. method:: encrypt(keys, data, outputfile="", armor=True) -> bytes:

                Encrypts the given data (either as str or bytes) via the list of keys or fingerprints. You can also just pass one single key or
                fingerprint. If you provide *outputfile* argument with a path, the encrypted output will be written to that path. By default the
                encrypted output is armored, but by passing *armor=False* you can get raw bytes returned.

                ::

                        >>> ks = jce.KeyStore("tests/files/store")
                        >>> key1 = ks.get_key("6AC6957E2589CB8B5221F6508ADA07F0A0F7BA99")
                        >>> key2 = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED621")
                        >>> encrypted = ks.encrypt([key1, key2], "Encrypted this string")
                        >>> assert encrypted.startswith(b"-----BEGIN PGP MESSAGE-----\n")

        .. method:: encrypt_file(keys, inputfilepath, outputfilepath, armor=True) -> bool:

                Returns `True` after encrypting the give *inputfilepath* to the *outputfilepath*.

                ::

                        >>> ks = jce.KeyStore("tests/files/store")
                        >>> key1 = ks.get_key("6AC6957E2589CB8B5221F6508ADA07F0A0F7BA99")
                        >>> key2 = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED621")
                        >>> assert ks.encrypt_file([key1, key2], "/tmp/data.txt", "/tmp/data.txt.asc")

        .. method:: decrypt(key, data, password="") -> bytes: 

                Returns the decrypted bytes from the given data and the secret key. You can either pass fingerprint or a secret `Key` object
                as the *key* argument.

                ::

                        >>> plain_bytes = ks.decrypt(secret_key2, encrypted_bytes, password=password)

        .. method:: decrypt_file(key, encrypted_path, outputfile, password=""):

                Decryptes the given *encrypted_path* and wrties the output to the *outputfile* path (both given as str).

                ::

                        >>> ks.decrypt_file(secret_key1, "/tmp/data.txt.asc", "/tmp/plain.txt", password=password)

        .. method:: delete_key(key: Union[str, Key]) -> None:

                Deletes the key based on the fingerprint or the Key object from the KeyStore.

                ::

                        >>> ks.delete_key("BB2D3F20233286371C3123D5209940B9669ED621")

                .. note:: Raises `KeyNotFoundError` if the key is not available in the KeyStore.

        .. method:: details() -> Tuple[int, int]:

                Returns a tuple containing the total number of public and secret keys available in the KeyStore.

        .. method:: get_all_keys() -> List[Key]:

                Returns a list of all the keys in the KeyStore.

        .. method:: get_key(fingerprint: str = "") -> Key:

                Returns a key from the keystore based on the fingerprint.
                Raises **KeyNotFoundError** if no such key available in the keystore.

        .. method:: get_keys(qvalue="", qtype="email") -> List[Key]:

                Returns a list of keys based on either email or name or value of the UIDs or URIs in the key (searchs on one of the terms first come basis).
                qtype can be one of the `email`, `value`, `name`, `uri`.

                ::

                        >>> keys_via_names = ks.get_keys(qvalue="test key", qtype="value")
                        >>> keys_via_email = ks.get_keys(qvalue="email@example.com")

        .. method:: import_cert(keypath: str) -> Key:

                Imports a pgp key file from a path on the system. 
                The method returns the newly import `Key` object to the caller.

                ::

                        >>> key = ks.import_cert("tests/files/store/public.asc")
                        >>> print(key)

        .. method:: sign(key, data, password) -> str:

                Signs the given *data* (can be either str or bytes) using the secret key. Returns the armored signature string.

        .. method:: sign_file(key, filepath, password, write=False) -> str:

                Returns the armored signature of the *filepath* argument using the secret key (either fingerprint or secret `Key` object).
                If you pass *write=True*, it will also write the armored signature to a file named as *filepath.asc* 

        .. method:: verify(key, data, signature) -> bool:

                Verifies the given *data* using the public key, and signature string, returns **True** or **False** as result. 

        .. method:: verify_file(key, filepath, signature_path) -> bool:

                Verifies the given filepath using the public key, and signature string, returns **True** or **False** as result. 


.. class:: Cipher() -> Cipher:

        This is the enum class to metion the type of ciphersuite to be used while creating a new key. Possible values are **Cipher.RSA4k**,
        **Cipher.RSA2k**, **Cipher.Cv25519**.

.. class:: Key(keyvalue: bytes, fingerprint: str, uids: Dict[str, str] = {}, keytype: KeyType=KeyType.PUBLIC, expirationtime=None, creationtime=None) -> Key:

        Returns a Key object  and fingerprint. The keytype enum :class:`KeyType`. 

        You can compare two key object with `==` operator.

        For most of the use cases you don't have to create one manually, but you can retrive one from the `KeyStore`.

        .. attribute:: keyvalue

                keyvalue holds the actual key as bytes.

        .. attribute:: fingerprint

                The string representation of the fingerprint

        .. attribute:: uids

                A dictionary holding all uids from the key.

        .. attribute:: creationtime

                The datetime.datetime object mentioning when the key was created.

        .. attribute:: expirationtime

                The datetime.datetime object mentioning when the key will expire or `None` otherwise.

        .. method:: get_pub_key() -> str:

                Returns the armored version of the public key as string.

.. class:: KeyType() -> KeyType:

        Enum class to mark if a key is public or private. Possible values are **KeyType.PUBLIC** and **KeyType.SECRET**.
