API Documentation
==================

For the rest of the documentation we assume that you imported the module as following.

::


        >>> import johnnycanencrypt as jce




.. class:: KeyStore(path: str) -> None:

        Returns a KeyStore object. This is the primary class of the module, and all high level usage is available via methods of this class.
        It takes a path to the directory where it stores/reads the keys. Please make sure that only the **user** has read/write capability
        to this path.

        The keys are represented inside the directory as either "fingerprint.pub" or "fingerprint.sec" file based on if it is a public or secret part
        of the key.

        If you can check for existance of any fingerprint (str) or `Key` object in the via `in` opertor.

        ::

                >>> ks = jce.KeyStore("/home/user/.pgpkeys")
                >>> "HEXFINGERPRINT" in ks


        .. method:: create_newkey(password: str, uid: str = "", ciphersuite: str = "RSA4k") -> Key:

                Returns the public part of the newly created `Key` in the store directory. You can mention ciphersuite as *RSA2k* or *RSA4k*,
                or *Cv25519*, while *RSA4k* is the default.

                ::

                        >>> ks = jce.KeyStore("/home/user/.pgpkeys")
                        >>> newkey = ks.create_newkey("supersecretpassphrasefromdiceware", "test key1 <email@example.com>", "RSA4k")

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

        .. method:: encrypt_file(self, keys, inputfilepath, outputfilepath, armor=True) -> bool:

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

        .. method:: delete_key(fingerprint: str, whichkey: Union["both", "public", "secret""]="both") -> None:

                Deletes the given key based on the fingerprint argument, by default it removes both the public and secret key. If you only want to remove
                the public or secret part, then pass *public* or *secret* to the **whichkey** argument.

                ::

                        >>> ks.delete_key("BB2D3F20233286371C3123D5209940B9669ED621")

        .. method:: details()

                Returns a tuple containing the total number of public and secret keys available in the KeyStore.

        .. method:: get_key(fingerprint: str = "", keytype: Union["public", "secret"] = "public") -> Key:

                Returns a key from the keystore based on the fingerprint and keytype. By default it returns the public key part.
                Raises **KeyNotFoundError** if no such key available in the keystore.

        .. method:: get_keys(email: str = "", name: str = "", value: str = "", keytype: str = "public") -> List[Key]:

                Returns a list of keys based on either email or name or value of the UIDs in the key (searchs on one of the terms first come basis).

                ::

                        >>> keys_via_names = ks.get_keys(name="test key")
                        >>> keys_via_email = ks.get_keys(email="email@example.com")

        .. method:: import_cert(keypath: str, onplace=False) -> Key:

                Imports a pgp key file from a path on the system. If the key is already in the correct format, and in the keystore directory,
                then you can *onplace=True*, otherwise it will be copied into the keystore directory. The method returns the newly import
                `Key` object to the caller.

                ::

                        >>> key = ks.import_cert("tests/files/store/public.asc")
                        >>> print(key)

        .. method:: sign(key, data, password) -> str:

                Signs the given *data* using the secret key. Returns the armored signature string.

        .. method:: sign_file(self, key, filepath, password, write=False) -> str:

                Returns the armored signature of the *filepath* argument using the secret key (either fingerprint or secret `Key` object).
                If you pass *write=True*, it will also write the armored signature to a file named as *filepath.asc* 

        .. method:: verify(key, data, signature) -> bool:

                Verifies the given *data* using the public key, and signature string, returns **True** or **False** as result. 

        .. method:: verify_file(key, filepath, signature_path) -> bool:

                Verifies the given filepath using the public key, and signature string, returns **True** or **False** as result. 


.. class:: Key(keypath: str, fingerprint: str, keytype: Union["public", "secret"])

        Returns a Key object based on the keypath and fingerprint. The keytype value decides if the key object is a `public` or `secret` key. It does
        not contain the actual key, but points to the right file path on the disk.

        You can compare two key object with `==` operator.

        For most of the use cases you don't have to create one manually, but you can retrive one from the `KeyStore`.



