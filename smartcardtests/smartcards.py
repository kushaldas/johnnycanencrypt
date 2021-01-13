#!/usr/bin/env python

# Currently we are only testing Cv25519 key based operations on smartcard in this code.

import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

import tempfile
import sys

from pprint import pprint

inp = input("Please make sure *TEST SMARTCARD* is connected and then type Yes to continue: ")
if inp != "Yes":
    sys.exit(0)


tempdir = tempfile.TemporaryDirectory()
ks = jce.KeyStore(tempdir.name)

print("Now importing the Cv25519 secret key to the keyring")
k = ks.import_cert("smartcardtests/5286C32E7C71E14C4C82F9AE0B207108925CB162.sec")

print(f"Creating temporary keyring at: {tempdir.name}")

print("Resetting Yubikey")
print(rjce.reset_yubikey())

print("setting the name")
rjce.set_name(b"Person<<Good", b"12345678")
rjce.set_url(b"https://kushaldas.in/great.asc", b"12345678")

print("Getting card information")
data = rjce.get_card_details()

assert data["name"] == "Person<<Good"
assert data["url"] == "https://kushaldas.in/great.asc"


print("Now uploading Cv25519 subkeys to the card")
rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
# Now get the data back
data = rjce.get_card_details()

print("Now verifying the fingerprints of the subkeys on the card")
assert jce.utils.convert_fingerprint(data["sig_f"]) == "30A697C27F90EAED0B78C8235E0BDC772A2CF037"
assert jce.utils.convert_fingerprint(data["enc_f"]) == "5D22EC7757DF42ED9C21AC9E7020C6D7B564D455"
assert jce.utils.convert_fingerprint(data["auth_f"]) == "50BAC98D4ADFD5D4485A1B04DEECB8B1546ED530"

print("Let us move to a new keystore directory")
tempdir = tempfile.TemporaryDirectory()
ks = jce.KeyStore(tempdir.name)

print("Now importing the Cv25519 public key to the keyring")
k = ks.import_cert("smartcardtests/5286C32E7C71E14C4C82F9AE0B207108925CB162.pub")
msg = b"OpenPGP on smartcard."
enc_bytes = ks.encrypt([k], msg)

print("Encrypted text: ")
print(enc_bytes)

print("Now trying to decrypt it via the smartcard")
returned_bytes = rjce.decrypt_bytes_on_card(k.keyvalue, enc_bytes, b"123456")

assert msg == returned_bytes
print("Decryption worked.")

print("Now let us sign some data")

signature = rjce.sign_bytes_detached_on_card(k.keyvalue, msg, b"123456")

if ks.verify(k, msg, signature):
    print("The signature is good.")
else:
    print("Bad signature from the card.")







