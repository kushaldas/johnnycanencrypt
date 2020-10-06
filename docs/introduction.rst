Introduction to johnnycanencrypt
================================

The module has 2 parts, one high level API, which can be directly accessed via importing the module. There is another
internal module with the same name (which is native in Rust), and has all the low level functions and classes.

We will import the module as jce.

::

        >>> import johnnycanencrypt as jce


The KeyStore
-------------

The module interacts over a `KeyStore` object, which points ot a directory path on the system. All keys available
as files on that directory ending with **.pub**, or **.asc**, or **.sec**. Below is an example where we are 
creating a keystore in an empty directory at "/var/lib/myapplication/keys", and then we will import a few keys in there.
For our example, we will use the keys from our tests directory.

::

        >>> ks = jce.KeyStore("/var/lib/myapplication/keys")
        >>> ks.import_cert("tests/files/store/secret.asc")
        <Key fingerprint=BB2D3F20233286371C3123D5209940B9669ED621 keytype=secret>
        >>> ks.import_cert("tests/files/store/pgp_keys.asc")
        <Key fingerprint=A85FF376759C994A8A1168D8D8219C8C43F6C5E1 keytype=public>
        >>> ks.import_cert("tests/files/store/public.asc")
        <Key fingerprint=BB2D3F20233286371C3123D5209940B9669ED621 keytype=public>

Now, if we check the directory from the shell, we will find the keys imported there.


::

        ❯ ls -l /var/lib/myapplication/keys
        .rw-rw-r--@ 9.5k user  6 Oct 18:48 A85FF376759C994A8A1168D8D8219C8C43F6C5E1.pub
        .rw-rw-r--@ 6.2k user  6 Oct 18:48 BB2D3F20233286371C3123D5209940B9669ED621.pub
        .rw-rw-r--@  11k user  6 Oct 18:47 BB2D3F20233286371C3123D5209940B9669ED621.sec

.. note:: This keystore directory is very much application specific. As a developer you should choose which directory on the system you will use
        as the key store. `SecureDrop <https://securedrop.org>`_ uses **/var/lib/securedrop/store** as their key storage (via gpg's python binding).

Encrypting and decrypting some bytes for a given fingerprint
-------------------------------------------------------------

::

        >>> key = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED621")
        >>> enc = ks.encrypt(key, "Sequoia is amazing.")
        >>> print(enc[:27])
        b'-----BEGIN PGP MESSAGE-----'
        >>> secret_key = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED621", "secret")
        >>> text = ks.decrypt(secret_key, enc, "redhat")
        >>> print(text)
        b'Sequoia is amazing.'
