#!/usr/bin/env python


import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

import tempfile
import sys
import os

from pprint import pprint

inp = input(
    "Please make sure *TEST SMARTCARD* is connected and then type Yes to continue: "
)
if inp != "Yes":
    sys.exit(0)


tempdir = tempfile.TemporaryDirectory()
ks = jce.KeyStore(tempdir.name)

print("Now importing the RSA4096 secret key to the keyring")
#k = ks.import_key("smartcardtests/2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12.sec")
k = ks.import_key("tests/files/primary_with_sign.asc")

print("Resetting Yubikey")
print(rjce.reset_yubikey())

print("setting the name")
rjce.set_name(b"Sign<<Primary", b"12345678")
rjce.set_url(b"https://kushaldas.in/great.asc", b"12345678")

print("Getting card information")
data = rjce.get_card_details()

assert data["name"] == "Sign<<Primary"
assert data["url"] == "https://kushaldas.in/great.asc"

print("Now uploading the primary key in the signing slot.")
rjce.upload_primary_to_smartcard(k.keyvalue, b"12345678", "redhat", whichslot=2)
print("Now uploading RSA subkeys to the card")
rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=1)
# Now get the data back
data = rjce.get_card_details()

print("Now verifying the fingerprints of the subkeys on the card")
print(    jce.utils.convert_fingerprint(data["sig_f"]) + " " + jce.utils.convert_fingerprint(data["enc_f"]) + " " + jce.utils.convert_fingerprint(data["auth_f"]))

