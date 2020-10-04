from .johnnycanencrypt import (
    Johnny,
    create_newkey,
    encrypt_bytes_to_file,
    parse_cert_file,
)
from .exceptions import KeyNotFoundError

import os
import shutil


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
        # These are our caches
        self.fingerprints_cache = {}
        self.secret_fingerprints_cache = {}
        # TODO: Create a proper searchable structure in future based on UIDs
        for filepath in os.listdir(self.path):
            fullpath = os.path.join(self.path, filepath)
            if fullpath[-4:] in [".asc", ".pub", ".sec"]:
                try:
                    uids, fingerprint, keytype = parse_cert_file(fullpath)
                except:
                    # TODO: Handle parsing error here
                    pass
                self.add_key_to_cache(fullpath, fingerprint, keytype)

    def add_key_to_cache(self, fullpath, fingerprint, keytype):
        if not keytype:
            self.fingerprints_cache[fingerprint] = Key(fullpath, fingerprint, "public")
        else:
            self.secret_fingerprints_cache[fingerprint] = Key(
                fullpath, fingerprint, "secret"
            )

    def import_cert(self, keypath: str, onplace=False):
        """Imports a given cert from the given path.

        :param path: Path to the pgp key file.
        :param onplace: Default value is False, if True means the keyfile is in the right directory
        """
        uids, fingerprint, keytype = parse_cert_file(keypath)

        if not onplace:
            # Here we should copy the key into our store
            finalpath = os.path.join(self.path, f"{fingerprint}")
            finalpath += ".sec" if keytype else ".pub"
            shutil.copy(keypath, finalpath)
        else:
            finalpath = keypath
        self.add_key_to_cache(finalpath, fingerprint, keytype)

    def details(self):
        "Returns tuple of (number_of_public, number_of_secret_keys)"
        return len(self.fingerprints_cache), len(self.secret_fingerprints_cache)

    def get_key(self, fingerprint: str = "", keytype: str = "public") -> Key:
        """Finds an existing public key based on the fingerprint. If the key can not be found on disk, then raises OSError.

        :param fingerprint: The fingerprint as str.
        :param keytype: str value either public or secret.
        """
        if keytype == "public":
            if fingerprint in self.fingerprints_cache:
                return self.fingerprints_cache[fingerprint]
        else:
            if fingerprint in self.secret_fingerprints_cache:
                return self.secret_fingerprints_cache[fingerprint]

        raise KeyNotFoundError(
            f"The key for {fingerprint} in not found in the keystore."
        )

    def create_newkey(
        self, password: str, uid: str = "", ciphersuite: str = "RSA4k"
    ) -> Key:
        """Returns a public `Key` object after creating a new key in the store

        :param password: The password for the key as str.
        :param uid: The text for the uid value as str.
        :param ciphersuite: Default RSA4k, other values are RSA2k, Cv25519
        """
        public, secret, fingerprint = create_newkey(password, uid, ciphersuite)
        # Now save the public key
        key_filename = os.path.join(self.path, f"{fingerprint}.pub")
        with open(key_filename, "w") as fobj:
            fobj.write(public)

        self.import_cert(key_filename, onplace=True)

        key = Key(key_filename, fingerprint)

        # Now save the secret key
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "w") as fobj:
            fobj.write(secret)

        self.import_cert(key_filename, onplace=True)

        return key
