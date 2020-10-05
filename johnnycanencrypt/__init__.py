from .johnnycanencrypt import (
    Johnny,
    create_newkey,
    encrypt_bytes_to_file,
    encrypt_bytes_to_bytes,
    parse_cert_file,
)
from .exceptions import KeyNotFoundError

import os
import shutil


def _delete_key_file(filepath):
    """Removes a file from disk"""
    try:
        os.remove(filepath)
    except FileNotFoundError:  # No issues if not found
        pass


class Key:
    "Returns a Key object."

    def __init__(self, keypath: str, fingerprint: str, keytype="public"):
        self.keypath = keypath
        self.keytype = keytype
        self.fingerprint = fingerprint

    def __repr__(self):
        return f"<Key fingerprint={self.fingerprint} keytype={self.keytype}>"

    def __eq__(self, value):
        """Two keys are same when fingerprint and keytype matches"""
        return self.fingerprint == value.fingerprint and self.keytype == value.keytype


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
        self.values_cache = {}
        self.emails_cache = {}
        self.names_cache = {}
        # TODO: Create a proper searchable structure in future based on UIDs
        for filepath in os.listdir(self.path):
            fullpath = os.path.join(self.path, filepath)
            if fullpath[-4:] in [".asc", ".pub", ".sec"]:
                try:
                    uids, fingerprint, keytype = parse_cert_file(fullpath)
                except Exception as e:
                    # TODO: Handle parsing error here
                    pass
                self.add_key_to_cache(fullpath, uids, fingerprint, keytype)

    def add_key_to_cache(self, fullpath, uids, fingerprint, keytype):
        "Populates the internal cache of the store"
        keys = self.fingerprints_cache.get(
            fingerprint, {"public": None, "secret": None}
        )
        if not keytype:
            key = Key(fullpath, fingerprint, "public")
            keys["public"] = key
            self.fingerprints_cache[fingerprint] = keys
        else:
            key = Key(fullpath, fingerprint, "secret")
            keys["secret"] = key
            self.fingerprints_cache[fingerprint] = keys

        # TODO: Now for each of the uid, add to the right dictionary

    def __contains__(self, other):
        """Checks if a Key object of fingerprint str exists in the keystore or not.

        :param other: Either fingerprint as str or `Key` object.
        :returns: boolean result
        """
        if type(other) == str:
            return other in self.fingerprints_cache
        elif type(other) == Key:
            return other.fingerprint in self.fingerprints_cache

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
        self.add_key_to_cache(finalpath, uids, fingerprint, keytype)

    def details(self):
        "Returns tuple of (number_of_public, number_of_secret_keys)"
        public = 0
        secret = 0
        for value in self.fingerprints_cache.values():
            if value["public"]:
                public += 1
            if value["secret"]:
                secret += 1
        return public, secret

    def get_key(self, fingerprint: str = "", keytype: str = "public") -> Key:
        """Finds an existing public key based on the fingerprint. If the key can not be found on disk, then raises OSError.

        :param fingerprint: The fingerprint as str.
        :param keytype: str value either public or secret.
        """
        if fingerprint in self.fingerprints_cache:
            key = self.fingerprints_cache[fingerprint]
        else:
            raise KeyNotFoundError(
                f"The key for {fingerprint} in not found in the keystore."
            )

        if keytype == "public":
            if key["public"]:
                return key["public"]
        else:
            if key["secret"]:
                return key["secret"]

        raise KeyNotFoundError(
            f"The {keytype} key for {fingerprint} in not found in the keystore."
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

    def delete_key(self, fingerprint: str, whichkey="both"):
        """Deletes a given key based on the fingerprint.

        :param fingerprint: str representation of the fingerprint
        :praram whichkey: By default it deletes both secret and public key, accepts, public, or secret as other arguments.
        """
        if not fingerprint in self:
            raise KeyNotFoundError(
                "The key for the given fingerprint={fingerprint} is not found in the keystore"
            )

        keys = self.fingerprints_cache[fingerprint]
        # First we remove from disk
        if whichkey == "public":
            k = keys["public"]
            _delete_key_file(k.keypath)
            keys["public"] = None
        elif whichkey == "secret":
            k = keys["secret"]
            _delete_key_file(k.keypath)
            keys["secret"] = None
        else:
            for k in keys.values():
                _delete_key_file(k.keypath)
            # Now from the cache
            del self.fingerprints_cache[fingerprint]
