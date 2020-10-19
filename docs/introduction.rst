Introduction to johnnycanencrypt
================================

The module has 2 parts, one high level API, which can be directly accessed via importing the module. There is another
internal module with the same name (which is native in Rust), and has all the low level functions and classes.

We will import the module as jce.

::

        >>> import johnnycanencrypt as jce


The KeyStore
-------------

The module interacts over a `KeyStore` object, which points ot a directory path
on the system. Inside of the directory, it will create a `jce.db` sqlite3
database if missing. Below is an example where we are creating a keystore in an
empty directory at "/var/lib/myapplication/keys", and then we will import a few
keys in there. For our example, we will use the keys from our tests directory.

::

        >>> ks = jce.KeyStore("/var/lib/myapplication/keys")
        >>> ks.import_cert("tests/files/store/secret.asc")
        <Key fingerprint=BB2D3F20233286371C3123D5209940B9669ED621 keytype=1>
        >>> ks.import_cert("tests/files/store/pgp_keys.asc")
        <Key fingerprint=A85FF376759C994A8A1168D8D8219C8C43F6C5E1 keytype=0>
        >>> ks.import_cert("tests/files/store/public.asc")
        <Key fingerprint=BB2D3F20233286371C3123D5209940B9669ED621 keytype=0>

Now, if we check the directory from the shell, we will find the keys imported there.


::

        ❯ ls -l /var/lib/myapplication/keys
        .rw-rw-r--@ 9.5k user  6 Oct 18:48 jce.db

.. note:: This keystore directory is very much application specific. As a developer you should choose which directory on the system you will use
        as the key store. `SecureDrop <https://securedrop.org>`_ uses **/var/lib/securedrop/store** as their key storage (via gpg's python binding).


.. warning:: This module does not handle keys still using `sha1` or `md5` for hash algorithms. If you are using any such old key, please generate new key
        and use them along wtih the module. `This function <https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html#method.reject_hash_at>`_ explains in some details why.


KeyStore path for the applicaitons which can run per user
----------------------------------------------------------

If you are writing a desktop application or any other tool which can have per user configuration, you should look into
the `base dir spec <https://specifications.freedesktop.org/basedir-spec/latest/>`_. If your application name is **myapplication**, then the store
path can be like: **$XDG_DATA_HOME/myapplication**.

Encrypting and decrypting some bytes for a given fingerprint
-------------------------------------------------------------

::

        >>> key = ks.get_key("BB2D3F20233286371C3123D5209940B9669ED621")
        >>> enc = ks.encrypt(key, "Sequoia is amazing.")
        >>> print(enc[:27])
        b'-----BEGIN PGP MESSAGE-----'
        >>> text = ks.decrypt(key, enc, "redhat")
        >>> print(text)
        b'Sequoia is amazing.'


Verify Tor Browser download using the signature and public key
---------------------------------------------------------------

In this example we will download the Tor Browser 10.0, and the signature and the public key using **wget**, and then verify via our module.

::

        wget https://www.torproject.org/dist/torbrowser/10.0/tor-browser-linux64-10.0_en-US.tar.xz
        wget https://www.torproject.org/dist/torbrowser/10.0/tor-browser-linux64-10.0_en-US.tar.xz.asc
        KEYURL=https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf
        wget $KEYURL -O kounek7zrdx745qydx6p59t9mqjpuhdf.pub


Now let us import the key and verify.

::

        >>> torkey = ks.import_cert("./kounek7zrdx745qydx6p59t9mqjpuhdf.pub")
        >>> torkey
        <Key fingerprint=EF6E286DDA85EA2A4BA7DE684E2C6E8793298290 keytype=0>
        >>> filepath="./tor-browser-linux64-10.0_en-US.tar.xz"
        >>> signaturepath="./tor-browser-linux64-10.0_en-US.tar.xz.asc"
        >>> ks.verify_file(torkey, filepath, signaturepath)
        True

