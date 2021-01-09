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


.. function:: reset_yubikey() -> bool:

        Returns `True` after successfully resetting a Yubikey.

        .. warning:: This is a dangerous function as it will destroy all the data in the card. Use it carefully.

.. function:: get_card_details() -> Dict[str, Any]:

        Returns a dictionary containing various card information in a dictionary.

        Available keys:
                - `serial_number`, the serial number of the card
                - `url`, for the public key url.
                - `sig_f` Signature key fingerprint
                - `enc_f` encryption key fingerprint
                - `auth_f` authentication key fingerprint

.. function:: change_user_pin(adminpin: bytes, newpin: bytes) -> bool:

        Changes the user pin to the given pin. The pin must be 6 chars or more. Requires current admin pin of the card.

.. function:: change_admin_pin(adminpin: bytes, newadminpin: bytes) -> bool:

        Changes the admin pin to the given pin. The pin must be 8 chars or more. Requires current admin pin of the card.


.. function:: set_name(name: bytes, pin: bytes) -> bool:

        Sets the name of the card holder (in bytes) in `surname<<firstname` format. The length must be less than 39 in size. Requires admin pin in bytes.

.. function:: set_url(url: bytes, pin: bytes) -> bool:

        Sets the public key URL on the card. Requires the admin pin in bytes.


.. function:: upload_to_smartcard(certdata: bytes, pin: bytes, password: str, whichkeys: int) -> bool:

        Uploads the marked (via whichkeys argument) subkeys to the smartcard. Takes the whole certdata (from `Key.keyvalue`) in bytes, and the admin pin of the card, the password (as string) of
        the key. You can choose which subkeys to be uploaded via the following values of `whichkeys` argument:

        - `1` for encryption
        - `2` for signing
        - `4` for authentication

        And then you can add them up for the required compbination. For example `7` means you want to upload all 3 kinds of subkeys, but `3` means only encryption and signing subkeys will be loaded into the smartcard.

        - `3` for both encryption and signing
        - `5` for encryption and authentication
        - `6` for signing and authentication
        - `7` for all 3 different subkeys

        ::

                import johnnycanencrypt as jce
                import johnnycanencrypt.johnnycanencrypt as rjce

                ks = jce.KeyStore("/tmp/demo")
                # By default it creates all 3 subkeys
                key = ks.create_newkey("redhat", ["First Last <fl@example.com>",], jce.Cipher.Cv25519)
                print(key.fingerprint)
                # We want to upload only the encryption and signing subkeys to the smartcard
                result = rjce.upload_to_smartcard(key.keyvalue, b"12345678", "redhat", 3)
                print(result)

