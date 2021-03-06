import os
import shutil
import sqlite3
import urllib.parse
from datetime import datetime
from enum import Enum
from pprint import pprint
from typing import Dict, List, Optional, Union, Tuple, Any

import httpx

from .exceptions import FetchingError, KeyNotFoundError
from .johnnycanencrypt import (
    CryptoError,
    Johnny,
    SameKeyError,
    create_newkey,
    encrypt_bytes_to_bytes,
    encrypt_bytes_to_file,
    encrypt_file_internal,
    encrypt_filehandler_to_file,
    get_pub_key,
    merge_keys,
    parse_cert_bytes,
    parse_cert_file,
)

import johnnycanencrypt.johnnycanencrypt as rjce

from .utils import (
    _get_cert_data,
    createdb,
    convert_fingerprint,
    to_sort_by_expiary,
    DB_UPGRADE_DATE,
)


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
        keyid: str,
        uids: List[Dict[str, Any]] = [],
        keytype: KeyType = KeyType.PUBLIC,
        expirationtime=None,
        creationtime=None,
        othervalues={},
        oncard: str = "",
    ):
        self.keyvalue = keyvalue
        self.keytype = keytype
        self.keyid = keyid
        self.fingerprint = fingerprint
        self.uids = uids
        self.expirationtime = (
            datetime.fromtimestamp(float(expirationtime)) if expirationtime else None
        )
        self.creationtime = (
            datetime.fromtimestamp(float(creationtime)) if creationtime else None
        )
        self.othervalues = othervalues
        self.oncard = oncard

    def __repr__(self):
        return f"<Key fingerprint={self.fingerprint} type={self.keytype.name}>"

    def __eq__(self, value):
        """Two keys are same when fingerprint and keytype matches"""
        return self.fingerprint == value.fingerprint and self.keytype == value.keytype

    def get_pub_key(self) -> str:
        "Returns the public key part as string"
        return get_pub_key(self.keyvalue)

    def available_subkeys(self) -> Tuple[bool, bool, bool]:
        "Returns bool tuple (enc, signing, auth)"
        subkeys_sorted = self.othervalues["subkeys_sorted"]
        got_enc = False
        got_sign = False
        got_auth = False
        # Loop over on the subkeys
        for subkey in subkeys_sorted:
            if subkey["revoked"]:
                continue
            if (
                subkey["expiration"] is not None
                and subkey["expiration"].date() > datetime.now().date()
            ):
                if subkey["keytype"] == "encryption":
                    got_enc = True
                    continue
                if subkey["keytype"] == "signing":
                    got_sign = True
                    continue
                if subkey["keytype"] == "authentication":
                    got_auth = True
                    continue
        # Now return the data
        return (got_enc, got_sign, got_auth)


class KeyStore:
    """Returns `KeyStore` class object, takes the directory path as string."""

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
                # we have to insert the date when this database schema was generated
                cursor.execute(
                    f"INSERT INTO dbupgrade (upgradedate) values (?)",
                    (DB_UPGRADE_DATE,),
                )
        else:
            # Now we have db already
            # verify if it has the same database schema
            self.upgrade_if_required()

    def upgrade_if_required(self):
        "Upgrades the database schema if required"
        SHOULD_WE = False
        existing_records = []
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        # First we will check if this db schema is old or not
        with con:
            cursor = con.cursor()
            sql = "SELECT * from dbupgrade"
            try:
                cursor.execute(sql)
                fromdb = cursor.fetchone()
                if fromdb["upgradedate"] < DB_UPGRADE_DATE:  # Means old db schema
                    SHOULD_WE = True
            except sqlite3.OperationalError:  # Means the table is not there.
                SHOULD_WE = True
            # Now check if we should upgrade if yes, then do this.
            if SHOULD_WE:
                # First read all the existing keys
                cursor.execute("SELECT * from KEYS")
                existing_records = cursor.fetchall()
            else:
                return
        # Temporay db setup
        oldpath = self.dbpath
        self.dbpath = os.path.join(self.path, "jce_upgrade.db")
        if os.path.exists(self.dbpath):  # Means the upgrade db already exist.
            # Unrecoverable error
            raise RuntimeError(
                f"{self.dbpath} already exists, please remove and then try again."
            )
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        with con:
            cursor = con.cursor()
            cursor.executescript(createdb)
            # we have to insert the date when this database schema was generated
            cursor.execute(
                f"INSERT INTO dbupgrade (upgradedate) values (?)", (DB_UPGRADE_DATE,)
            )
        # now let us insert our existing data
        for row in existing_records:
            (
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            ) = parse_cert_bytes(row["keyvalue"])
            self._save_key_info_to_db(
                row["keyvalue"],
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            )
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        with con:
            cursor = con.cursor()
            for row in existing_records:
                oncard = row["oncard"]
                fingerprint = row["fingerprint"]
                sql = "UPDATE keys set oncard=? where fingerprint=?"
                cursor.execute(sql, (oncard, fingerprint))
        # Now let us rename the file
        os.rename(self.dbpath, oldpath)
        self.dbpath = oldpath

    def update_password(self, key: Key, password: str, newpassword: str) -> Key:
        """Updates the password of the given key and saves to the database"""
        cert = rjce.update_password(key.keyvalue, password, newpassword)
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        with con:
            cursor = con.cursor()
            sql = "UPDATE keys set keyvalue=? where fingerprint=?"
            cursor.execute(sql, (cert, key.fingerprint))
        assert cert != key.keyvalue
        key.keyvalue = cert
        return key

    def add_key_file_to_db(
        self,
        fullpath,
        uids,
        fingerprint,
        keytype,
        expirationtime=None,
        creationtime=None,
        subkeys=[],
    ):
        "Populates the internal database of the store from a keyfile"
        with open(fullpath, "rb") as fobj:
            cert = fobj.read()
        self._save_key_info_to_db(
            cert, uids, fingerprint, keytype, expirationtime, creationtime, subkeys
        )

    def _save_key_info_to_db(
        self,
        cert,
        uids,
        fingerprint,
        keytype,
        expirationtime,
        creationtime,
        othervalues,
    ):
        "Saves all information given to the SQLite3 database"
        etime = str(expirationtime.timestamp()) if expirationtime else ""
        ctime = str(creationtime.timestamp()) if creationtime else ""
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        ktype = 1 if keytype else 0
        subkeys = othervalues["subkeys"]
        mainkeyid = othervalues["keyid"]
        with con:
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
                    uids, fp, kt, et, ct, othervalues = parse_cert_bytes(newcert)
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
                sql = "INSERT INTO keys (keyvalue, fingerprint, keyid, keytype, expiration, creation) VALUES(?, ?, ?, ?, ?, ?)"
                cursor.execute(sql, (cert, fingerprint, mainkeyid, ktype, etime, ctime))
                key_id = cursor.lastrowid

            # Now let us add the subkey and keyid details
            sql = "INSERT INTO subkeys (key_id, fingerprint, keyid, expiration, creation, keytype, revoked) VALUES(?, ?, ?, ?, ?, ?, ?)"
            for subkey in subkeys:
                ctime = str(subkey[2].timestamp()) if subkey[2] else ""
                etime = str(subkey[3].timestamp()) if subkey[3] else ""
                cursor.execute(
                    sql,
                    (key_id, subkey[1], subkey[0], etime, ctime, subkey[4], subkey[5]),
                )

            # TODO: Now for each of the uid, add to the right dictionary
            for uid_keyname in ["name", "value", "email", "uri"]:
                tablename = f"uid{uid_keyname}s"
                # First delete all old ones
                cursor.execute(f"DELETE from {tablename} where key_id=?", (key_id,))
            for uid in uids:
                # First we will insert the value
                if "value" in uid and uid["value"]:
                    revoked = 1 if uid["revoked"] else 0
                    sql = f"INSERT INTO uidvalues (value, revoked, key_id) values (?, ?, ?)"
                    cursor.execute(sql, (uid["value"], revoked, key_id))
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

    def add_userid(self, key: Key, userid: str, password: str) -> Key:
        """Adds a new user id to the given key, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param uid: The string value to add the keybobject
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")
        # A list of UID values which is already in the database
        olduids = [uid["value"] for uid in key.uids]
        # Now add the new userid to the cert in binary formart
        newcert = rjce.add_uid_in_cert(key.keyvalue, userid.encode("utf-8"), password)

        # Now we will parse the new cert bytes so that we can get the actual value for the user id
        # Expensive, but works.
        (
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = parse_cert_bytes(newcert)
        # To make sure we actually have a secret key
        assert keytype == True
        # Let us write the new keydata to the disk
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "wb") as fobj:
            fobj.write(newcert)
        con = sqlite3.connect(self.dbpath)
        with con:
            cursor = con.cursor()
            # First let us update the actual keyvalue
            sql = "UPDATE keys set keyvalue=? where fingerprint=?"
            cursor.execute(sql, (newcert, key.fingerprint))
            # Now we need the key_id from the database table
            cursor.execute(
                "SELECT id from keys where fingerprint=?", (key.fingerprint,)
            )
            fromdb = cursor.fetchone()
            key_id = fromdb[0]
            # Now loop through the new userids and find the new one
            for uid in uids:
                if "value" in uid and uid["value"]:
                    # First check if we are already there in the old list or not.
                    if uid["value"] in olduids:
                        continue
                    # Ok, now we have a new user id, we can start adding this value to the database
                    # this next line does not make sense for a new user id :)
                    revoked = 1 if uid["revoked"] else 0
                    sql = f"INSERT INTO uidvalues (value, revoked, key_id) values (?, ?, ?)"
                    cursor.execute(sql, (uid["value"], revoked, key_id))
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

        # Regnerate the key object and return it
        return self.get_key(fingerprint)

    def revoke_userid(self, key: Key, userid: str, password: str) -> Key:
        """Revokes the given user id to the given key, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param userid: The string value to add the keybobject
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")
        # Now revoke the given userid to the cert in binary formart
        newcert = rjce.revoke_uid_in_cert(
            key.keyvalue, userid.encode("utf-8"), password
        )

        # Now we will parse the new cert bytes so that we can get the actual value for the user id
        # Expensive, but works.
        (
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = parse_cert_bytes(newcert)
        # To make sure we actually have a secret key
        assert keytype == True
        # Let us write the new keydata to the disk
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "wb") as fobj:
            fobj.write(newcert)
        con = sqlite3.connect(self.dbpath)
        with con:
            cursor = con.cursor()
            # First let us update the actual keyvalue
            sql = "UPDATE keys set keyvalue=? where fingerprint=?"
            cursor.execute(sql, (newcert, key.fingerprint))
            sql = "SELECT id FROM uidvalues WHERE key_id=(SELECT id FROM keys where fingerprint=?) AND value=?"
            # Now loop through the new userids and find the new one
            cursor.execute(
                sql, (key.fingerprint, userid)
            )  # Now we will mark this userid as revoked
            fromdb = cursor.fetchone()
            value_id = fromdb[0]

            revoked = 1
            sql = "UPDATE uidvalues set revoked=? where id=?"
            cursor.execute(sql, (revoked, value_id))

        # Regnerate the key object and return it
        return self.get_key(fingerprint)

    def import_cert(self, keypath: str, onplace=False) -> Key:
        """Imports a given cert from the given path.

        :param path: Path to the pgp key file.
        :param onplace: Default value is False, if True means the keyfile is in the right directory
        """
        (
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = parse_cert_file(keypath)

        self.add_key_file_to_db(
            keypath,
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
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
            return self._internal_build_key_list(rows, cursor)

    def get_keys_by_keyid(self, keyid: str):
        "Returns a list of keys for a given KeyID"
        # TODO: This has bad SQL, we can improve in future.
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        list_of_db_ids = set()
        with con:
            cursor = con.cursor()
            sql = "SELECT * FROM keys WHERE keyid=?"
            cursor.execute(sql, (keyid,))
            rows = cursor.fetchall()
            for row in rows:
                list_of_db_ids.add(row["id"])

            sql = "SELECT * FROM subkeys WHERE keyid=?"
            cursor.execute(sql, (keyid,))
            rows = cursor.fetchall()
            for row in rows:
                list_of_db_ids.add(row["key_id"])
            # Now the final search
            result = []
            sql = "SELECT * FROM keys WHERE id=?"
            for key_id in list(list_of_db_ids):
                cursor.execute(sql, (key_id,))
                rows = cursor.fetchall()
                result.extend(self._internal_build_key_list(rows, cursor))

            if not result:
                KeyNotFoundError(f"The key with keyid {keyid} is not found.")
            return result

    def _internal_build_key_list(self, rows, cursor):
        "Internal method to create a list of keys from db result rows"
        finalresult = []
        for result in rows:
            if result:
                key_id = result["id"]
                cert = result["keyvalue"]
                fingerprint = result["fingerprint"]
                keyid = result["keyid"]
                expirationtime = result["expiration"]
                creationtime = result["creation"]
                keytype = KeyType.SECRET if result["keytype"] else KeyType.PUBLIC
                oncard = result["oncard"]

                # Now get the uids
                sql = "SELECT id, value, revoked FROM uidvalues WHERE key_id=?"
                cursor.execute(sql, (key_id,))
                rows = cursor.fetchall()
                uids = []
                for row in rows:
                    value_id = row["id"]
                    revoked = True if row["revoked"] == 1 else False
                    email = self._get_one_row_from_table(cursor, "uidemails", value_id)
                    name = self._get_one_row_from_table(cursor, "uidnames", value_id)
                    uri = self._get_one_row_from_table(cursor, "uiduris", value_id)
                    uids.append(
                        {
                            "value": row["value"],
                            "revoked": revoked,
                            "email": email,
                            "name": name,
                            "uri": uri,
                        }
                    )

                # Get the subkeys
                sql = "SELECT fingerprint, keyid, expiration, creation, keytype, revoked FROM subkeys WHERE key_id=?"
                cursor.execute(sql, (key_id,))
                rows = cursor.fetchall()
                othervalues = {}
                subs = {}
                sort_subkeys = []
                # Each subkey is added as a tuple
                # Remember that there can be many expired subkeys.
                # TODO: Add a value to mark if it was alive at the time of the call
                for row in rows:
                    etime = (
                        datetime.fromtimestamp(float(row["expiration"]))
                        if row["expiration"]
                        else None
                    )
                    ctime = (
                        datetime.fromtimestamp(float(row["creation"]))
                        if row["creation"]
                        else None
                    )
                    subs[row["keyid"]] = (
                        row["fingerprint"],
                        etime,
                        ctime,
                        row["keytype"],
                        bool(row["revoked"]),
                    )
                    sort_subkeys.append(
                        {
                            "keyid": row["keyid"],
                            "fingerprint": row["fingerprint"],
                            "expiration": etime,
                            "creation": ctime,
                            "keytype": row["keytype"],
                            "revoked": bool(row["revoked"]),
                        }
                    )

                sort_subkeys.sort(key=lambda x: to_sort_by_expiary(x), reverse=True)
                othervalues["subkeys"] = subs
                # TODO: We need a testcase for the sorted subkeys
                othervalues["subkeys_sorted"] = sort_subkeys

                finalresult.append(
                    Key(
                        cert,
                        fingerprint,
                        keyid,
                        uids,
                        keytype,
                        expirationtime,
                        creationtime,
                        othervalues,
                        oncard,
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
        uids: Optional[Union[List[str], str]] = [],
        ciphersuite: Cipher = Cipher.RSA4k,
        creation=None,
        expiration=None,
        subkeys_expiration=False,
        whichkeys=7,
    ) -> Key:
        """Returns a public `Key` object after creating a new key in the store

        :param password: The password for the key as str.
        :param uids: The text for the uid values as List of str. This can be none.
        :param ciphersuite: Default Cipher.RSA4k, other values are Cipher.RSA2k, Cipher.Cv25519
        :param creation: datetime.datetime, default datetime.now() (via rust)
        :param expiration: datetime.datetime, default 0 (Never)
        :param subkeys_expiration: Bool (default False), pass True if you want to set the expiary date to the subkeys instead of master key.
        :param whichkeys: Decides which all subkeys to generate, 1 (for encryption), 2 for signing, 4 for authentication. Add the numbers for mixed result.
        """
        if creation:
            ctime = creation.timestamp()
        else:
            ctime = 0

        if expiration:
            etime = expiration.timestamp()
        else:
            etime = 0
        finaluids = []
        if isinstance(uids, str):
            if uids:
                finaluids.append(uids)
        elif isinstance(uids, list):
            finaluids = uids

        public, secret, fingerprint = create_newkey(
            password,
            finaluids,
            ciphersuite.value,
            int(ctime),
            int(etime),
            subkeys_expiration,
            whichkeys,
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

        # now let us check if the key is public and has a corresponding smartcard with secret
        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            return rjce.decrypt_bytes_on_card(
                k.keyvalue, data, password.encode("utf-8")
            )

        # Otherwise, we use the standard ondisk secret
        jp = Johnny(k.keyvalue)
        return jp.decrypt_bytes(data, password)

    def encrypt_file(self, keys, inputfilepath, outputfilepath, armor=True):
        """Encrypts the given data with the list of keys and writes in the output file.

        :param keys: List of fingerprints or Key objects
        :param inputfilepath: Path of the input file to be encrypted
        :param outputfilepath: output file path
        :param armor: Default is True, for armored output.
        """
        check_path = False
        use_filehandler = False

        # This is when we receive str
        if isinstance(inputfilepath, str):
            check_path = True
            inputfile = inputfilepath.encode("utf-8")
        # This is when we receive bytes
        elif isinstance(inputfilepath, bytes):
            check_path = True
            inputfile = inputfilepath
        else:  # This is when we receive opened file handler
            fh = inputfilepath
            use_filehandler = True
        if check_path:  # Only verify if it is a file path
            if not os.path.exists(inputfilepath):
                raise FileNotFoundError(f"{inputfilepath} can not be found.")

        if type(keys) != list:
            finalkeys = [
                keys,
            ]
        else:
            finalkeys = keys
        final_key_paths = self._find_keys(finalkeys)

        # For encryption to a file
        if type(outputfilepath) == str:
            encrypted_file = outputfilepath.encode("utf-8")
        else:
            encrypted_file = outputfilepath

        if not use_filehandler:
            encrypt_file_internal(final_key_paths, inputfile, encrypted_file, armor)
        else:
            encrypt_filehandler_to_file(final_key_paths, fh, encrypted_file, armor)
        return True

    def decrypt_file(self, key, encrypted_path, outputfile, password=""):
        """Decryptes the given file to the output path.

        :param key: Fingerprint or secret Key object
        :param encrypted_path:: Path of the encrypted file, or the opened file handler in binary mode
        :param outputfile: Decrypted output file path as str
        :param password: Password for the secret key
        """
        use_filehandler = False
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key)
        else:
            k = key

        if type(encrypted_path) == str:
            inputfile = encrypted_path.encode("utf-8")
        elif isinstance(encrypted_path, bytes):
            inputfile = encrypted_path
        else:
            fh = encrypted_path
            use_filehandler = True

        if type(outputfile) == str:
            outputpath = outputfile.encode("utf-8")
        else:
            outputpath = outputfile

        # now let us check if the key is public and has a corresponding smartcard with secret
        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            if use_filehandler:
                return rjce.decrypt_filehandler_on_card(
                    k.keyvalue, fh, outputpath, password.encode("utf-8")
                )
            else:
                return rjce.decrypt_file_on_card(
                    k.keyvalue, inputfile, outputpath, password.encode("utf-8")
                )

        jp = Johnny(k.keyvalue)
        if not use_filehandler:
            return jp.decrypt_file(inputfile, outputpath, password)
        else:
            return jp.decrypt_filehandler(fh, outputpath, password)

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

        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            return rjce.sign_bytes_detached_on_card(
                k.keyvalue, data, password.encode("utf-8")
            )

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
        signature = ""
        if type(key) == str:  # Means we have a fingerprint
            k = self.get_key(key)
        else:
            k = key

        if type(filepath) == str:
            filepath_in_bytes = filepath.encode("utf-8")
        else:
            filepath_in_bytes = filepath

        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            signature = rjce.sign_file_detached_on_card(
                k.keyvalue, filepath_in_bytes, password.encode("utf-8")
            )

        else:
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

    def fetch_key_by_fingerprint(self, fingerprint: str):
        """Fetches key from keys.openpgp.org based on the fingerprint.

        :param fingerprint: The fingerprint string without the leading 0x and in upper case.

        :returns: Key object if found or else raises KeyNotFoundError
        """
        # First remove any leading 0x
        if fingerprint.startswith("0x"):
            fingerprint = fingerprint[2:]
        # make it uppercase
        fingerprint = fingerprint.upper()
        url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}"
        return self._internal_fetch_from_server(url, fingerprint)

    def fetch_key_by_email(self, email: str):
        """Fetches key from keys.openpgp.org based on the fingerprint.

        :param email: The email address to search

        :returns: Key object if found or else raises KeyNotFoundError
        """
        # encode the email address
        email = urllib.parse.quote(email)
        url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
        return self._internal_fetch_from_server(url, email)

    def _internal_fetch_from_server(self, url: str, term: str) -> Key:
        resp = httpx.get(url)
        if resp.status_code == 404:
            raise KeyNotFoundError(
                f"The given search term {term} was found in the server."
            )

        elif resp.status_code == 200:
            cert = resp.text.encode("utf-8")
            (
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            ) = parse_cert_bytes(cert)

            self._save_key_info_to_db(
                cert,
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            )
            return self.get_key(fingerprint)
        else:
            raise FetchingError(f"Server returned: {resp.status_code}")

    def sync_smartcard(self):
        """
        Syncs the attached smartcard to the right public keys in the KeyStore.

        :returns: The fingerprint of the primary key.
        """
        data = rjce.get_card_details()
        if not data["serial_number"]:
            return "No data found."
        con = sqlite3.connect(self.dbpath)
        con.row_factory = sqlite3.Row
        with con:
            cursor = con.cursor()
            # First let us check if a key already exists
            sql = "SELECT DISTINCT key_id, fingerprint FROM subkeys where fingerprint IN (?, ?, ?)"
            sig_f = convert_fingerprint(data["sig_f"])
            enc_f = convert_fingerprint(data["enc_f"])
            auth_f = convert_fingerprint(data["auth_f"])
            cursor.execute(sql, (sig_f, enc_f, auth_f))
            fromdb = cursor.fetchone()
            if fromdb:
                # Means we found the main key, now we have to mark it with the serial number of the card
                sql = "UPDATE keys SET oncard=? WHERE id=?"
                cursor.execute(sql, (data["serial_number"], fromdb["key_id"]))
                sql = "SELECT fingerprint from keys where id=?"
                cursor.execute(sql, (fromdb["key_id"],))
                result = cursor.fetchone()
                return result["fingerprint"]
