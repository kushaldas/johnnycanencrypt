import os
import shutil
import sqlite3
from datetime import datetime
from enum import Enum
from pprint import pprint
from typing import Dict, List, Union

from .exceptions import KeyNotFoundError
from .johnnycanencrypt import (
    CryptoError,
    Johnny,
    SameKeyError,
    create_newkey,
    encrypt_bytes_to_bytes,
    encrypt_bytes_to_file,
    encrypt_file_internal,
    get_pub_key,
    merge_keys,
    parse_cert_bytes,
    parse_cert_file,
)
from .utils import _get_cert_data, createdb


class KeyType(Enum):
    PUBLIC = 0
    SECRET = 1


class Cipher(Enum):
    RSA4k = "RSA4k"
    RSA2k = "RSA2k"
    Cv25519 = "Cv25519"


class Key:
    "Returns a Key object."

    def __init__(
        self,
        keyvalue: bytes,
        fingerprint: str,
        uids: Dict[str, str] = {},
        keytype: KeyType = KeyType.PUBLIC,
        expirationtime=None,
        creationtime=None,
    ):
        self.keyvalue = keyvalue
        self.keytype = keytype
        self.fingerprint = fingerprint
        self.uids = uids
        self.expirationtime = (
            datetime.fromtimestamp(float(expirationtime)) if expirationtime else None
        )
        self.creationtime = (
            datetime.fromtimestamp(float(creationtime)) if creationtime else None
        )

    def __repr__(self):
        return f"<Key fingerprint={self.fingerprint} type={self.keytype.name}>"

    def __eq__(self, value):
        """Two keys are same when fingerprint and keytype matches"""
        return self.fingerprint == value.fingerprint and self.keytype == value.keytype

    def get_pub_key(self) -> str:
        "Returns the public key part as string"
        return get_pub_key(self.keyvalue)


class KeyStore:
    """Returns `KeyStore` class object, takes the directory path as string.
    """

    def __init__(self, path: str) -> None:
        fullpath = os.path.abspath(path)
        if not os.path.exists(fullpath):
            raise OSError(f"The {fullpath} does not exist.")
        self.dbpath = os.path.join(fullpath, "jce.db")
        self.path = fullpath
        if not os.path.exists(self.dbpath):
            con = sqlite3.connect(self.dbpath)
            with con:
                cursor = con.cursor()
                cursor.executescript(createdb)

    def add_key_to_cache(
        self,
        fullpath,
        uids,
        fingerprint,
        keytype,
        expirationtime=None,
        creationtime=None,
    ):
        "Populates the internal cache of the store"
        etime = str(expirationtime.timestamp()) if expirationtime else ""
        ctime = str(creationtime.timestamp()) if creationtime else ""
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        ktype = 1 if keytype else 0
        with con:
            with open(fullpath, "rb") as fobj:
                cert = fobj.read()
            cursor = con.cursor()
            # First let us check if a key already exists
            sql = "SELECT * FROM keys where fingerprint=?"
            cursor.execute(sql, (fingerprint,))
            fromdb = cursor.fetchone()
            if fromdb:  # Means a key is there in the db
                key_id = fromdb["id"]
                sql = "UPDATE keys SET keyvalue=?, keytype=?, expiration=?, creation=? WHERE id=?"
                if (
                    fromdb["keytype"] == 0
                ):  # only update if there is a public key in the store
                    key = self.get_key(fingerprint)
                    newcert = merge_keys(key.keyvalue, cert)
                    uids, fp, kt, et, ct = parse_cert_bytes(newcert)
                    etime = str(et.timestamp()) if et else ""
                    ctime = str(ct.timestamp()) if ct else ""
                else:  # Means another secret to replace
                    # We will not do anything, if you want reimport for a secret key
                    # delete the old one, and import the new one
                    # TODO: We should also raise SameKeyError here
                    return

                cursor.execute(sql, (cert, ktype, etime, ctime, key_id))
            else:
                # Now insert the new key
                sql = "INSERT INTO keys (keyvalue, fingerprint, keytype, expiration, creation) VALUES(?, ?, ?, ?, ?)"
                cursor.execute(sql, (cert, fingerprint, ktype, etime, ctime))
                key_id = cursor.lastrowid

            # TODO: Now for each of the uid, add to the right dictionary
            for uid_keyname in ["name", "value", "email", "uri"]:
                tablename = f"uid{uid_keyname}s"
                # First delete all old ones
                cursor.execute(f"DELETE from {tablename} where key_id=?", (key_id,))
            for uid in uids:
                # First we will insert the value
                if "value" in uid and uid["value"]:
                    sql = f"INSERT INTO uidvalues (value, key_id) values (?, ?)"
                    cursor.execute(sql, (uid["value"], key_id))
                    value_id = cursor.lastrowid
                else:
                    # If no value, then we can skip the rest
                    continue
                for uid_keyname in ["name", "email", "uri"]:
                    if uid_keyname in uid and uid[uid_keyname]:
                        tablename = f"uid{uid_keyname}s"
                        value = uid[uid_keyname]
                        sql = f"INSERT INTO {tablename} (value, key_id, value_id) values (?, ?, ?)"
                        cursor.execute(sql, (value, key_id, value_id))

    def __contains__(self, other: Union[str, Key]) -> bool:
        """Checks if a Key object of fingerprint str exists in the keystore or not.

        :param other: Either fingerprint as str or `Key` object.
        :returns: boolean result
        """
        fingerprint = ""
        if type(other) == str:
            assert isinstance(other, str)
            fingerprint = other
        elif type(other) == Key:
            assert isinstance(other, Key)
            fingerprint = other.fingerprint
        try:
            if self.get_key(fingerprint):
                return True
        except KeyNotFoundError:
            return False
        return False

    def import_cert(self, keypath: str, onplace=False) -> Key:
        """Imports a given cert from the given path.

        :param path: Path to the pgp key file.
        :param onplace: Default value is False, if True means the keyfile is in the right directory
        """
        uids, fingerprint, keytype, expirationtime, creationtime = parse_cert_file(
            keypath
        )

        self.add_key_to_cache(
            keypath, uids, fingerprint, keytype, expirationtime, creationtime
        )
        return self.get_key(fingerprint)

    def details(self):
        "Returns tuple of (number_of_public, number_of_secret_keys)"
        public = 0
        secret = 0
        con = sqlite3.connect(self.dbpath)
        with con:
            cursor = con.cursor()
            cursor.execute("SELECT id, fingerprint, keytype from keys")
            rows = cursor.fetchall()
            for row in rows:
                if row[2]:
                    secret += 1
                else:
                    public += 1
        return public, secret

    def get_key(self, fingerprint: str = "") -> Key:
        """Finds an existing public key based on the fingerprint. If the key can not be found on disk, then raises OSError.

        :param fingerprint: The fingerprint as str.
        """
        return self._internal_get_key(fingerprint)[0]

    def _internal_get_key(self, fingerprint="", key_id=None, allkeys=False):
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        finalresult = []
        with con:
            cursor = con.cursor()
            if fingerprint:
                sql = "SELECT * FROM keys WHERE fingerprint=?"
                cursor.execute(sql, (fingerprint,))
            elif key_id:
                sql = "SELECT * FROM keys WHERE id=?"
                cursor.execute(sql, (key_id,))
            else:  # means get all keys
                sql = "SELECT * FROM keys"
                cursor.execute(sql)
            rows = cursor.fetchall()
            for result in rows:
                if result:
                    key_id = result["id"]
                    cert = result["keyvalue"]
                    fingerprint = result["fingerprint"]
                    expirationtime = result["expiration"]
                    creationtime = result["creation"]
                    keytype = KeyType.SECRET if result["keytype"] else KeyType.PUBLIC

                    # Now get the uids
                    sql = "SELECT id, value FROM uidvalues WHERE key_id=?"
                    cursor.execute(sql, (key_id,))
                    rows = cursor.fetchall()
                    uids = []
                    for row in rows:
                        value_id = row["id"]
                        email = self._get_one_row_from_table(
                            cursor, "uidemails", value_id
                        )
                        name = self._get_one_row_from_table(
                            cursor, "uidnames", value_id
                        )
                        uri = self._get_one_row_from_table(cursor, "uiduris", value_id)
                        uids.append(
                            {
                                "value": row["value"],
                                "email": email,
                                "name": name,
                                "uri": uri,
                            }
                        )

                    finalresult.append(
                        Key(
                            cert,
                            fingerprint,
                            uids,
                            keytype,
                            expirationtime,
                            creationtime,
                        )
                    )
            if finalresult:
                return finalresult

            raise KeyNotFoundError(f"The key(s) not found in the keystore.")

    def _get_one_row_from_table(self, cursor, tablename, value_id):
        "Internal function to select different uid items"
        sql = f"SELECT value FROM {tablename} where value_id={value_id}"
        cursor.execute(sql)
        result = cursor.fetchone()
        if result:
            return result["value"]
        else:
            return ""

    def get_all_keys(self) -> List[Key]:
        "Returns a list of keys"
        return self._internal_get_key(allkeys=True)

    def get_keys(self, qvalue: str, qtype: str = "email") -> List[Key]:
        """Finds an existing public key based on the email, or name or value (in this order). If the key can not be found on disk, then raises OSError.

        :param qvalue: Query text
        :param qtype: The type of the query, default email, other values are value, name or uri.

        :returns: A list of keys or empty list.
        """
        if not qtype in ["email", "value", "uri", "name"]:
            raise CryptoError("We need at least one of the email/name/value/uri.")

        results = []
        unique_fingerprints = {}
        # TODO: Now let us search
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        with con:
            cursor = con.cursor()
            if qtype == "value":
                sql = "SELECT id, key_id FROM uidvalues where value=?"
                cursor.execute(sql, (qvalue,))
                rows = cursor.fetchall()
                for row in rows:
                    key_id = row["key_id"]
                    key = self._internal_get_key(key_id=key_id)[0]
                    if not key.fingerprint in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "email":
                sql = "SELECT id, key_id FROM uidemails where value=?"
                cursor.execute(sql, (qvalue,))
                rows = cursor.fetchall()
                for row in rows:
                    key_id = row["key_id"]
                    key = self._internal_get_key(key_id=key_id)[0]
                    if not key.fingerprint in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "name":
                sql = "SELECT id, key_id FROM uidenames where value=?"
                cursor.execute(sql, (qvalue,))
                rows = cursor.fetchall()
                for row in rows:
                    key_id = row["key_id"]
                    key = self._internal_get_key(key_id=key_id)[0]
                    if not key.fingerprint in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "uri":
                sql = "SELECT id, key_id FROM uiduris where value=?"
                cursor.execute(sql, (qvalue,))
                rows = cursor.fetchall()
                for row in rows:
                    key_id = row["key_id"]
                    key = self._internal_get_key(key_id=key_id)[0]
                    if not key.fingerprint in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
        return results

    def create_newkey(
        self,
        password: str,
        uid: str = "",
        ciphersuite: Cipher = Cipher.RSA4k,
        creation=None,
        expiration=None,
    ) -> Key:
        """Returns a public `Key` object after creating a new key in the store

        :param password: The password for the key as str.
        :param uid: The text for the uid value as str.
        :param ciphersuite: Default Cipher.RSA4k, other values are Cipher.RSA2k, Cipher.Cv25519
        :param creation: datetime.datetime, default datetime.now() (via rust)
        :param expiration: datetime.datetime, default 0 (Never)
        """
        if creation:
            ctime = creation.timestamp()
        else:
            ctime = 0

        if expiration:
            etime = expiration.timestamp()
        else:
            etime = 0
        public, secret, fingerprint = create_newkey(
            password, uid, ciphersuite.value, int(ctime), int(etime)
        )
        # Now save the secret key
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "w") as fobj:
            fobj.write(secret)

        key = self.import_cert(key_filename)

        # TODO: should we remove the key_filename from the disk?
        return key

    def delete_key(self, key: Union[str, Key]):
        """Deletes a given key based on the fingerprint.

        :param key: Either str representation of the fingerprint or a Key object
        """
        if type(key) == str:
            assert isinstance(key, str)
            fingerprint = key
        elif type(key) == Key:
            assert isinstance(key, Key)
            fingerprint = key.fingerprint
        else:
            raise TypeError(f"Wrong datatype for {key}")

        if not fingerprint in self:
            raise KeyNotFoundError(
                "The key for the given fingerprint={fingerprint} is not found in the keystore"
            )
        con = sqlite3.connect(self.dbpath)
        with con:
            cursor = con.cursor()
            cursor.execute("DELETE FROM keys where fingerprint=?", (fingerprint,))

    def _find_keys(self, keys):
        "To find all the key paths"
        final_keys = []
        for k in keys:
            if type(k) == str:  # Means fingerprint
                key = self.get_key(k)
                final_keys.append(key.keyvalue)
            else:
                final_keys.append(k.keyvalue)
        return final_keys

    def encrypt(self, keys, data, outputfile="", armor=True):
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
        final_key_paths = self._find_keys(finalkeys)
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

    def decrypt(self, key, data, password=""):
        """Decrypts the given bytes and returns plain text bytes.

        :param key: Fingerprint or secret Key object
        :param data: Encrypted data in bytes.
        :param password: Password for the secret key
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key)
        else:
            k = key

        jp = Johnny(k.keyvalue)
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
        final_key_paths = self._find_keys(finalkeys)

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
            k = self.get_key(key)
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

        jp = Johnny(k.keyvalue)
        return jp.decrypt_file(inputfile, outputpath, password)

    def sign(self, key, data, password):
        """Signs the given data with the key.

        :param key: Fingerprint or secret Key object
        :param data: Data to be signed.
        :param password: Password of the secret key file.

        :returns: The signature as string
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key)
        else:
            k = key

        if type(data) == str:
            data = data.encode("utf-8")
        jp = Johnny(k.keyvalue)
        return jp.sign_bytes_detached(data, password)

    def verify(self, key, data, signature):
        """Verifies the given data and the signature

        :param key: Fingerprint or public Key object
        :param data: Data to be signed.
        :param signature: Signature text

        :returns: Boolean
        """
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key)
        else:
            k = key

        if type(data) == str:
            data = data.encode("utf-8")
        jp = Johnny(k.keyvalue)
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
            k = self.get_key(key)
        else:
            k = key

        if type(filepath) == str:
            filepath_in_bytes = filepath.encode("utf-8")
        else:
            filepath_in_bytes = filepath
        jp = Johnny(k.keyvalue)
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
            k = self.get_key(key)
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
        jp = Johnny(k.keyvalue)
        return jp.verify_file(filepath, signature_in_bytes)
