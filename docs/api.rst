API Documentation
==================

For the rest of the documentation we assume that you imported the module as following.

::


        >>> import johnnycanencrypt as jce




.. class:: KeyStore(path: str) -> None:

        Returns a KeyStore object. This is the primary class of the module, and
        all high level usage is available via methods of this class. It takes a
        path to the directory where it stores/reads the keys. Please make sure
        that only the **user** has read/write capability to this path.

        The keys are represented inside the directory in the **jce.db** sqlite3
        database. Every time there is any change in the DB schema, we
        automatically create a temporary database called **jce_upgrade.db** in
        the same path, and then reimport all the keys, and rename the file and
        continue with the steps. This is one time operation when we do a new
        release.

        You can check for existance of any fingerprint (str) or `Key` object in the via `in` opertor.

        ::

                >>> ks = jce.KeyStore("/var/lib/myamazingapp")
                >>> "HEXFINGERPRINT" in ks


        .. method:: add_userid(key: Key, userid: str, password: str) -> Key:

                Returns the updated key with a new userid. If you need to upload the key to the https://keys.openpgp.org, then remember to
                have to an email address in the user id.

        .. method:: certify_key(key: Union[Key, str], otherkey: Union[Key, str], uids: List[str], sig_type: SignatureType = SignatureType.GenericCertification, password: str = "", oncard=False) -> Key:

                This method signs the given list of userid(s) in `otherkey` using the primary key of the `key`, by default it signs as *SignatureType.GenericCertification*, but you can do other types too. If the primary key is on a smartcard, then pass `oncard=True`, default value is `False`.

        .. method:: create_key(password: str, uids: Optional[Union[List[str], str]] = [], ciphersuite: Cipher = Cipher.RSA4k, creation: Optional[datetime.datetime] = None, expiration: Optional[datetime.datetime] = None, subkeys_expiration= False, whichkeys = 7, can_primary_sign: bool = False, can_primary_expire=False) -> Key:

                Returns the public part of the newly created `Key` in the store
                directory. You can mention ciphersuite :class:`Cipher`  as
                *Cipher.RSA2k* or *Cipher.RSA4k*, or *Cipher.Cv25519*, while
                *Cipher.RSA4k* is the default. You can also provide
                `datetime.datetime` objects for creation time and expiration
                time. By default it will use the current time as creation time,
                and keys don't expire. You can provide a string for uid, or multiple
                strings using a List for multiple uids. It can also create a key without
                any uids.

                If you want the primary key to have signing capability, then pass `can_primary_sign=True`.

                You can pass `whichkeys = 1` to generate only the encryption subkey, 2 for signing, 4 for authentication.
                By default it will create all three subkeys (7).

                ::

                        >>> ks = jce.KeyStore("/var/lib/myamazingapp")
                        >>> newkey = ks.create_key("supersecretpassphrasefromdiceware", "test key1 <email@example.com>", jce.KeyType.RSA4k)

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

        .. method:: encrypt_file(keys, inputfilepath: Union[str,bytes,BinaryIO], outputfilepath: Union[str, bytes], armor=True) -> bool:

                Returns `True` after encrypting the given *inputfilepath* to the *outputfilepath*. The *inputfilepath* could be `str`, or `bytes`, or a opened file handler for bytes.

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


        .. method:: decrypt_file(key, encrypted_path: Union[str,bytes,BinaryIO], outputfile, password=""):

                Decryptes the given *encrypted_path* and wrties the output to the *outputfile* path (both given as str or bytes). In the *encrypted_path* can be an opened file handler to read
                binary data.

                ::

                        >>> ks.decrypt_file(secret_key1, "/tmp/data.txt.asc", "/tmp/plain.txt", password=password)
                        >>> with open("/tmp/hello.gpg", "rb") as fobj:
                        ...     ks.decrypt_file(secret_key1, fobj, "/tmp/plain.txt", password=password)
        

        .. method:: delete_key(key: Union[str, Key]) -> None:

                Deletes the key based on the fingerprint or the Key object from the KeyStore.

                ::

                        >>> ks.delete_key("BB2D3F20233286371C3123D5209940B9669ED621")

                .. note:: Raises `KeyNotFoundError` if the key is not available in the KeyStore.

        .. method:: details() -> Tuple[int, int]:

                Returns a tuple containing the total number of public and secret keys available in the KeyStore.

        .. method:: fetch_key_by_email(email: str) -> Key:

                Searches and retrives a key at https://keys.openpgp.org based on the given email address. Current limit is 1 email address can be
                searched only once per minute. The key is also stored in the local keystore. Raises `KeyNotFoundError` if the key is not found.

        .. method:: fetch_key_by_fingerprint(fingerprint: str) -> Key:

                Searches and retrives a key at https://keys.openpgp.org based on the given fingerprint, one can search 6 times per minute. Raises
                `KeyNotFoundError` if the key is not found.

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

        .. method:: get_keys_by_keyid(keyid: str) -> List[Key]:

                Returns a list of keys matching with the keyids, first directly
                checks the master keys and then subkeys. Raises
                **KeyNotFoundError** in case no such keyid is found on the
                store.

        .. method:: import_key(keypath: str) -> Key:

                Imports a pgp key file from a path on the system. 
                The method returns the newly import `Key` object to the caller.

                ::

                        >>> key = ks.import_key("tests/files/store/public.asc")
                        >>> print(key)

        .. method:: revoke_userid(key: Key, userid: str, pass: str) -> Key:

                Revokes the given user id from the given secret key and returns the updated key.

        .. method:: update_expiry_in_subkeys(key: Key, subkeys: List[str], expiration: datetime, password: str) -> Key:

                Updates the expiry time for the given subkeys (as a list of fingerprints) for the given secret key.

        .. method:: sign_detached(key, data, password) -> str:

                Signs the given *data* (can be either str or bytes) using the secret key. Returns the armored signature string.

        .. method:: sign_file_detached(key, filepath, password, write=False) -> str:

                Returns the armored signature of the *filepath* argument using the secret key (either fingerprint or secret `Key` object).
                If you pass *write=True*, it will also write the armored signature to a file named as *filepath.asc* 

        .. method:: verify(key, data: Union[str, bytes], signature:Optional[str]) -> bool:

                Verifies the given *data* using the public key, and signature string if given, returns **True** or **False** as result.

        .. method:: verify_file_detached(key: Union[str, Key], filepath: Union[str, bytes], signature_path) -> bool:

                Verifies the given *filepath* using the public key, and signature string, returns **True** or **False** as result.

        .. method:: verify_file(key, filepath) -> bool:

                Verifies the given signed *filepath* using the public key, returns **True** or **False** as result.

        .. method:: verify_and_extract_bytes(key: Union[str, Key], data: Union[str, bytes]) -> bytes:

                Verifies the given signed *data* using the public key,  returns the actual data as bytes.

        .. method:: verify_and_extract_file(self, key: Union[str, Key], filepath: Union[str, bytes], output: Union[str, bytes]) -> bool::

                Verifies the given signed *filepath* and writes the actual data in *output*.


.. class:: Cipher() -> Cipher:

        This is the enum class to metion the type of ciphersuite to be used while creating a new key. Possible values are **Cipher.RSA4k**,
        **Cipher.RSA2k**, **Cipher.Cv25519**.

.. class:: Key(keyvalue: bytes, fingerprint: str, uids: Dict[str, str] = {}, keytype: KeyType=KeyType.PUBLIC, expirationtime=None, creationtime=None, othervalues={}, oncard: str = "", can_primary_sign: bool = False, primary_on_card: str = "") -> Key:

        Returns a Key object  and fingerprint. The keytype enum :class:`KeyType`. 

        You can compare two key object with `==` operator.

        For most of the use cases you don't have to create one manually, but you can retrive one from the `KeyStore`.

        .. attribute:: keyvalue

                keyvalue holds the actual key as bytes.

        .. attribute:: fingerprint

                The string representation of the fingerprint

        .. attribute:: uids

                A dictionary holding all uids from the key, also stores related **certification** of the given uids.

        .. attribute:: creationtime

                The datetime.datetime object mentioning when the key was created.

        .. attribute:: expirationtime

                The datetime.datetime object mentioning when the key will expire or `None` otherwise.

        .. method:: get_pub_key() -> str:

                Returns the armored version of the public key as string.

        .. attribute:: keyid

                The keyid of the master key

        .. attribute:: primary_on_card

                A string containing the smartcard ID, this will be populated only after `sync_smartcard` call in the `KeyStore`.

        .. attribute:: oncard

                A string containing the smartcard ID if the card contains any of the subkeys, this will be populated only after `sync_smartcard` call in the `KeyStore`.

        .. attribute:: othervalues

                A dictionary containing subkeys's keyids and fingerprints.
        
        .. attribute:: can_primary_sign

                A boolean value telling if the primary key has signing capability or not.

        .. method:: available_subkeys() -> Tuple[bool, bool, bool]:

                Returns a tuple with 3 boolean values as (got_enc, got_sign, got_auth) to tell us which all subkeys are available.
                The subkeys will not be expired keys (based on the date of the system) and also not revoked.

.. class:: KeyType() -> KeyType:

        Enum class to mark if a key is public or private. Possible values are **KeyType.PUBLIC** and **KeyType.SECRET**.

.. class:: SignatureType() -> SignatureType:

        Enum class to mark the kind of certification one can do on another key. Possible values are **SignatureType.GenericCertification**,
        **SignatureType.PersonaCertification**, **SignatureType.CasualCertification**, **SignatureType.PositiveCertification**.


.. function:: get_card_touch_policies() -> List[TouchMode]

        Returns a list of Enum values from TouchMode. To be used to determine the touch capabilities of the smartcard.
        Remember to verify this list before calling :func:`set_keyslot_touch_policy`.

