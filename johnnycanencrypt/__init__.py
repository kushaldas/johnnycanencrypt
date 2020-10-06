from .johnnycanencrypt import (
    Johnny,
    create_newkey,
    encrypt_bytes_to_file,
    encrypt_bytes_to_bytes,
    encrypt_file_internal,
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
        else:
            key = Key(fullpath, fingerprint, "secret")
            keys["secret"] = key
        # Now set the fingerprint cache
        self.fingerprints_cache[fingerprint] = keys

        # TODO: Now for each of the uid, add to the right dictionary
        for uid in uids:
            for uid_keyname, cache in [
                ("value", self.values_cache),
                ("email", self.emails_cache),
                ("name", self.names_cache),
            ]:
                if uid_keyname in uid and uid[uid_keyname]:
                    value = uid[uid_keyname]
                    keys = cache.get(value, {"public": [], "secret": []})
                    if not keytype:
                        keys["public"].append(key)
                    else:
                        keys["secret"].append(key)
                    # Now set the values cache
                    cache[value] = keys

    def __contains__(self, other):
        """Checks if a Key object of fingerprint str exists in the keystore or not.

        :param other: Either fingerprint as str or `Key` object.
        :returns: boolean result
        """
        if type(other) == str:
            return other in self.fingerprints_cache
        elif type(other) == Key:
            return other.fingerprint in self.fingerprints_cache

    def import_cert(self, keypath: str, onplace=False) -> Key:
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
        return self.get_key(fingerprint, "secret" if keytype else "public")

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

    def get_keys(
        self, email: str = "", name: str = "", value: str = "", keytype: str = "public"
    ) -> Key:
        """Finds an existing public key based on the email, or name or value (in this order). If the key can not be found on disk, then raises OSError.

        :param email: The email as str.
        :param name: The name as str.
        :param value: The value as str.
        :param keytype: str value either public or secret.

        :returns: A list of keys or empty list.
        """
        if email:
            search_item, cache = email, self.emails_cache

        elif name:
            search_item, cache = name, self.names_cache

        elif value:
            search_item, cache = value, self.values_cache
        else:
            raise RuntimeError("We need at least one of the email/name/value.")
        # Now let us search
        if search_item in cache:
            keys = cache[search_item]
        else:
            raise KeyNotFoundError(
                f"The key for {search_item} in not found in the keystore."
            )

        if keytype == "public":
            return keys["public"]
        else:
            return keys["secret"]

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

    def _find_key_paths(self, keys):
        "To find all the key paths"
        final_key_paths = []
        for k in keys:
            if type(k) == str:  # Means fingerprint
                key = self.get_key(k)
                final_key_paths.append(key.keypath)
            else:
                final_key_paths.append(k.keypath)
        return final_key_paths

    def encrypt_bytes(self, keys, data, outputfile="", armor=True):
        """Encrypts the given data with the list of keys and returns the output.

        :param keys: List of fingerprints or Key objects
        :param data: data to be encrtypted, either str or bytes
        :param outputfile: If provided the output will be wriiten in the location.
        :param armor: Default is True, for armored output.
        """
        if type(keys) != list:
            finalkeys = [
                keys,
            ]
        else:
            finalkeys = keys
        final_key_paths = self._find_key_paths(finalkeys)
        # Check if we return data
        if type(data) == str:
            finaldata = data.encode("utf-8")
        else:
            finaldata = data
        if not outputfile:
            return encrypt_bytes_to_bytes(final_key_paths, finaldata, armor)

        # For encryption to a file
        if type(outputfile) == str:
            encrypted_file = outputfile.encode("utf-8")
        else:
            encrypted_file = outputfile

        encrypt_bytes_to_file(final_key_paths, finaldata, encrypted_file, armor)
        return True

    def decrypt_bytes(self, key, data, password=""):
        """Decryptes the given bytes and returns plain text bytes.

        :param key: Fingerprint or secret Key object
        :param data: Encrypted data in bytes.
        :param password: Password for the secret key
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="secret")
        else:
            k = key

        jp = Johnny(k.keypath)
        return jp.decrypt_bytes(data, password)

    def encrypt_file(self, keys, inputfilepath, outputfilepath, armor=True):
        """Encrypts the given data with the list of keys and writes in the output file.

        :param keys: List of fingerprints or Key objects
        :param inputfilepath: Path of the input file to be encrypted
        :param outputfilepath: output file path
        :param armor: Default is True, for armored output.
        """
        if not os.path.exists(inputfilepath):
            raise FileNotFoundError(f"{inputfilepath} can not be found.")

        if type(keys) != list:
            finalkeys = [
                keys,
            ]
        else:
            finalkeys = keys
        final_key_paths = self._find_key_paths(finalkeys)

        if type(inputfilepath) == str:
            inputfile = inputfilepath.encode("utf-8")
        else:
            inputfile = inputfilepath

        # For encryption to a file
        if type(outputfilepath) == str:
            encrypted_file = outputfilepath.encode("utf-8")
        else:
            encrypted_file = outputfilepath

        encrypt_file_internal(final_key_paths, inputfile, encrypted_file, armor)
        return True

    def decrypt_file(self, key, encrypted_path, outputfile, password=""):
        """Decryptes the given file to the output path.

        :param key: Fingerprint or secret Key object
        :param encrypted_path:: Path of the encrypted file
        :param outputfile: Decrypted output file path as str
        :param password: Password for the secret key
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="secret")
        else:
            k = key

        if type(encrypted_path) == str:
            inputfile = encrypted_path.encode("utf-8")
        else:
            inputfile = encrypted_path

        if type(outputfile) == str:
            outputpath = outputfile.encode("utf-8")
        else:
            outputpath = outputfile

        jp = Johnny(k.keypath)
        return jp.decrypt_file(inputfile, outputpath, password)

    def sign(self, key, data, password):
        """Signs the given data with the key.

        :param key: Fingerprint or secret Key object
        :param data: Data to be signed.
        :param password: Password of the secret key file.

        :returns: The signature as string
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="secret")
        else:
            k = key

        if type(data) == str:
            data = data.encode("utf-8")
        jp = Johnny(k.keypath)
        return jp.sign_bytes_detached(data, password)

    def verify(self, key, data, signature):
        """Verifies the given data and the signature

        :param key: Fingerprint or public Key object
        :param data: Data to be signed.
        :param signature: Signature text

        :returns: Boolean
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="public")
        else:
            k = key

        if type(data) == str:
            data = data.encode("utf-8")
        jp = Johnny(k.keypath)
        return jp.verify_bytes(data, signature.encode("utf-8"))

    def sign_file(self, key, filepath, password, write=False):
        """Signs the given data with the key. It also writes filename.asc in the same directory of the file as the signature if write value is True.

        :param key: Fingerprint or secret Key object
        :param filepath: str value of the path to the file.
        :param password: Password of the secret key file.
        :param wrtie: boolean value (default False), determines if we should write the signature to a file.

        :returns: The signature as string
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="secret")
        else:
            k = key

        if type(filepath) == str:
            filepath_in_bytes = filepath.encode("utf-8")
        else:
            filepath_in_bytes = filepath
        jp = Johnny(k.keypath)
        signature = jp.sign_file_detached(filepath_in_bytes, password)

        # Now check if we have to write the file on disk
        if write:
            sig_file_name = filepath + ".asc"
            with open(sig_file_name, "w") as fobj:
                fobj.write(signature)

        return signature

    def verify_file(self, key, filepath, signature_path):
        """Verifies the given filepath based on the signature file.

        :param key: Fingerprint or public Key object
        :param filepath: File to be verified.
        :param signature_path: Path to the signature file.

        :returns: Boolean
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key, keytype="public")
        else:
            k = key

        if not os.path.exists(signature_path):
            raise FileNotFoundError(
                f"The signature file at {signature_path} is missing."
            )
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file at {filepath} is missing.")

        # Let us read the signature
        with open(signature_path, "rb") as fobj:
            signature_in_bytes = fobj.read()

        if type(filepath) == str:
            filepath = filepath.encode("utf-8")
        jp = Johnny(k.keypath)
        return jp.verify_file(filepath, signature_in_bytes)
