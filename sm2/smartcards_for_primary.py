#!/usr/bin/env python


import argparse
import os
import sys
import tempfile
from pprint import pprint

import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

# Only run on GitHub CI or with --local flag
def check_environment():
    parser = argparse.ArgumentParser(description="Smartcard tests for primary key")
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run locally (requires physical smartcard)",
    )
    args = parser.parse_args()

    is_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"

    if not is_ci and not args.local:
        print("This script only runs on GitHub CI or with --local flag.")
        print("Usage: python smartcards_for_primary.py --local")
        sys.exit(0)

check_environment()

PUBLIC_KEY = "tests/files/primary_with_sign_public.asc"


tempdir = tempfile.TemporaryDirectory()
ks = jce.KeyStore(tempdir.name)

print("Now importing the RSA4096 secret key to the keyring")
# k = ks.import_key("smartcardtests/2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12.sec")
k = ks.import_key("tests/files/primary_with_sign.asc")

# We are writing the public key on disk
with open(PUBLIC_KEY, "w") as fobj:
    fobj.write(k.get_pub_key())

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
#rjce.set_keyslot_touch_policy(b"12345678", rjce.KeySlot.Signature, rjce.TouchMode.Fixed)
# Now get the data back
data = rjce.get_card_details()

print("Now verifying the fingerprints of the subkeys on the card")
print(
    jce.utils.convert_fingerprint(data["sig_f"])
    + " "
    + jce.utils.convert_fingerprint(data["enc_f"])
    + " "
    + jce.utils.convert_fingerprint(data["auth_f"])
)

print("Now let us sign some data")

msg = b"Kushal loves Python."
signature = rjce.sign_bytes_detached_on_card(k.keyvalue, msg, b"123456")

print(f"The signature is {signature}")

if ks.verify(k, msg, signature):
    print("The signature is good.")
else:
    print("Bad signature from the card.")

print("Let us move to a new temporary directory")
tempdir = tempfile.TemporaryDirectory()
ks = jce.KeyStore(tempdir.name)

print("Now importing the PUBLIC key to the keyring")
#

k = ks.import_key(PUBLIC_KEY)
ks.sync_smartcard()
other = ks.import_key("tests/files/store/kushal_updated_key.asc")

newother = ks.certify_key(
    k,
    other,
    [
        "Kushal Das <kushaldas@riseup.net>",
    ],
    jce.SignatureType.PersonaCertification,
    password="123456",
    oncard=True,
)
with open("hello.public", "wb") as f:
    f.write(newother.keyvalue)
