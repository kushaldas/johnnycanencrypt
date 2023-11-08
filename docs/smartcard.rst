Smartcard access
=================

Johnnycanencrypt provides limilted smardcard access for OpenPGP operations.
This is built on top of the `3.4.1 spec <https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf>`_.


We only tested the code against `Yubikey 5 <https://www.yubico.com/products/yubikey-5-overview/>`_ and Yubikey 4 series.

.. note:: Remember the `Cv25519` keys will only work on Yubikey 5 series.

The part of the code is written in Rust, so you will have to import the internal `johnnycanencrypt` module.

::

        import johnnycanencrypt.johnnycanencrypt as rjce

Smartcard API
--------------

.. class:: KeySlot

    These are the available KeySlots in a card.

   .. py:attribute:: Signature
   .. py:attribute:: Encryption
   .. py:attribute:: Authentication
   .. py:attribute:: Attestation



.. class:: TouchMode

    The different touch mode for a key.

   .. py:attribute:: Off
   .. py:attribute:: On
   .. py:attribute:: Fixed
   .. py:attribute:: Cached
   .. py:attribute:: CachedFixed



.. function:: set_keyslot_touch_policy(adminpin: bytes, slot: KeySlot, mode: TouchMode) -> bool:

        Sets the given `TouchMode` to the slot. Returns False if it is already set as Fixed.

.. important:: Remember to verify the available touch modes via :func:`get_card_touch_policies` first.

.. function:: get_keyslot_touch_policy(slot: KeySlot) -> TouchMode:

        Returns the available `TouchMode` of the given slot in the smartcard.

.. function:: get_card_version() -> tuple[int, int, int]:

        Returns a tuple containing the Yubikey firmware version. Example: (5,2,7) or (4,3,1).

.. function:: reset_yubikey() -> bool:

        Returns `True` after successfully resetting a Yubikey.

        .. warning:: This is a dangerous function as it will destroy all the data in the card. Use it carefully.

.. function:: get_card_details() -> Dict[str, Any]:

        Returns a dictionary containing various card information in a dictionary.

        Available keys:
                - `serial_number`, the serial number of the card
                - `url`, for the public key url.
                - `name`, the card holder's name, surname<<<firstname
                - `PW1`, number of user pin retries left
                - `RC`, number of reset pin retries left 
                - `PW2`, number of admin pin retries left
                - `signatures`, total number signatures made by the card
                - `sig_f` Signature key fingerprint
                - `enc_f` encryption key fingerprint
                - `auth_f` authentication key fingerprint

.. function:: change_user_pin(adminpin: bytes, newpin: bytes) -> bool:

        Changes the user pin to the given pin. The pin must be 6 chars or more. Requires current admin pin of the card.

.. function:: change_admin_pin(adminpin: bytes, newadminpin: bytes) -> bool:

        Changes the admin pin to the given pin. The pin must be 8 chars or more. Requires current admin pin of the card.

.. function:: decrypt_bytes_on_card(certdata: bytes, data: bytes, pin:bytes): -> bytes

        Decryptes the given encrypted bytes using the smartcard. You will have to pass
        the public key as the *certdata* argument.

.. function:: decrypt_file_on_card(certdata: bytes, filepath: bytes, output: bytes, pin:bytes): -> None

        Decryptes the given *filepath* and writes the output to the given *output* path using the smartcard. You will have to pass
        the public key as the *certdata* argument.

.. function:: decrypt_filehandler_on_card(certdata: bytes, fh: typing.IO, output: bytes, pin:bytes): -> None

        Decryptes the given opened *fh* and writes the output to the given *output* path using the smartcard. You will have to pass
        the public key as the *certdata* argument.

        .. note:: This function first reads the whole file and then decrypts it. So, try to use the `decrypt_file_on_card` function instead.

.. function:: is_smartcard_connected() -> bool:

        Returns `True` if it can find a Yubikey attached to the system, or else returns `False`.

.. function:: set_name(name: bytes, pin: bytes) -> bool:

        Sets the name of the card holder (in bytes) in `surname<<firstname` format. The length must be less than 39 in size. Requires admin pin in bytes.

.. function:: set_url(url: bytes, pin: bytes) -> bool:

        Sets the public key URL on the card. Requires the admin pin in bytes.

.. function:: sign_bytes_detached_on_card(certdata: bytes, data: bytes, pin: bytes) -> str:

        Signs the given bytes on the card, and returns the detached signature as base64 encoded string. Also requires the public key in `certdata` argument.

.. function:: sign_bytes_on_card(certdata: bytes, data: bytes, pin: bytes) -> bytes:

        Signs the given bytes on the card, and returns the signed bytes. Also requires the public key in `certdata` argument.

.. function:: sign_file_detached_on_card(certdata: bytes, filepath: bytes, pin: bytes) -> str:

        Signs the given filepath and returns the detached signature as base64 encoded string. Also requires the the public in `certdata` argument.

.. function:: sign_file_on_card(certdata: bytes, filepath: bytes, output: bytes, pin: bytes, cleartext: bool) -> bool:

        Signs the given filepath and writes to output. Also requires the the public in `certdata` argument. For things like email, you would want to sign them in clear text.

.. function:: upload_to_smartcard(certdata: bytes, pin: bytes, password: str, whichkeys: int) -> bool:

        Uploads the marked (via whichkeys argument) subkeys to the smartcard. Takes the whole certdata (from `Key.keyvalue`) in bytes, and the admin pin of the card, the password (as string) of
        the key. You can choose which subkeys to be uploaded via the following values of `whichkeys` argument:

        - `1` for encryption
        - `2` for signing
        - `4` for authentication

        And then you can add them up for the required combination. For example `7` means you want to upload all 3 kinds of subkeys, but `3` means only encryption and signing subkeys will be loaded into the smartcard.

        - `3` for both encryption and signing
        - `5` for encryption and authentication
        - `6` for signing and authentication
        - `7` for all 3 different subkeys

        ::

                import johnnycanencrypt as jce
                import johnnycanencrypt.johnnycanencrypt as rjce

                ks = jce.KeyStore("/tmp/demo")
                # By default it creates all 3 subkeys
                key = ks.create_key("redhat", ["First Last <fl@example.com>",], jce.Cipher.Cv25519)
                print(key.fingerprint)
                # We want to upload only the encryption and signing subkeys to the smartcard
                result = rjce.upload_to_smartcard(key.keyvalue, b"12345678", "redhat", 3)
                print(result)

.. function:: upload_primary_to_smartcard(certdata: bytes, pin: bytes, password: str, whichslot: int) -> bool:

        Uploads the primary key to the smartcard in the given slot. Takes the whole certdata (from `Key.keyvalue`) in bytes, and the admin pin of the card, the password (as string) of
        the key. You can choose which subkeys to be uploaded via the following values of `whichslot` argument:

        - `2` for signing slot
        - `4` for authentication slot

        ::

                import johnnycanencrypt as jce
                import johnnycanencrypt.johnnycanencrypt as rjce

                ks = jce.KeyStore("/tmp/demo")
                # Create a primary key with signing capability & an encryption subkey
                key = ks.create_key("redhat", ["First Last <fl@example.com>",], jce.Cipher.Cv25519, whichkeys=1, can_primary_sign=True)
                print(key.fingerprint)
                # We want to upload first the primary key to the signing slot of the card
                result = rjce.upload_primary_to_smartcard(key.keyvalue, b"12345678", "redhat", whichslot=2)
                # We want to upload only the encryption subkey to the smartcard
                result = rjce.upload_to_smartcard(key.keyvalue, b"12345678", "redhat", 1)
                print(result)

