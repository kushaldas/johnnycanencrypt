from .johnnycanencrypt import Johnny, create_newkey, encrypt_bytes_to_file
from .exceptions import KeyNotFoundError

import os

class Key:
    "Returns a Key object."

    def __init__(self, keypath: str, fingerprint: str, keytype="public"):
        self.keypath = keypath
        self.keytype = keytype
        self.fingerprint = fingerprint


class KeyStore:
    """Returns `KeyStore` class object, takes the directory path as string.
    """

    def __init__(self, path: str) -> None:
        fullpath = os.path.abspath(path)
        if not os.path.exists(fullpath):
            raise OSError(f"The {fullpath} does not exist.")
        self.path = fullpath

    def get_key(self, fingerprint: str = "", keytype: str = "public") -> Key:
        """Finds an existing public key based on the fingerprint. If the key can not be found on disk, then raises OSError.

        :param fingerprint: The fingerprint as str.
        :param keytype: str value either public or secret.
        """
        if keytype == "public":
            key_filename = f"{fingerprint}.pub"
        else:
            key_filename = f"{fingerprint}.sec"
        full_key_path = os.path.join(self.path, key_filename)
        if not os.path.exists(full_key_path):
            raise KeyNotFoundError(f"The {keytype} key for {fingerprint} is not found.")
        k = Key(full_key_path, fingerprint, keytype)
        return k

    def create_newkey(self, password: str, uid: str = "") -> Key:
        """Returns a public `Key` object after creating a new key in the store

        :param password: The password for the key as str.
        :param uid: The text for the uid value as str.
        """
        public, secret, fingerprint = create_newkey(password, uid)
        # Now save the public key
        key_filename = os.path.join(self.path, f"{fingerprint}.pub")
        with open(key_filename, "w") as fobj:
            fobj.write(public)

        key = Key(key_filename, fingerprint)

        # Now save the secret key
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "w") as fobj:
            fobj.write(public)

        return key
