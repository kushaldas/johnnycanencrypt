import os
import pytest

import johnnycanencrypt.johnnycanencrypt as rjce

from .conftest import BASE_TESTSDIR
from .utils import _get_cert_data

NISTP256_PUB = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEje+CqtHn9yp/vHBahLv01IeqS+6ZnD7ZQ87nAZZU6xPzTk5npdCq6q+mJBNsi/CNcV2H2Y1EuzsP1JylRyYqA= 123456\n"
NISTP384_PUB = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC2Xg9NOPD5HoHP3ee22gzhd2oAgRTx5EQFHuRS3jn/3MyJ8YYUeV8/i9+Xs7OTt6FsyVKDVCvelNqE6x1+aCKE0TblNCp9X9p7M8AegIobmEMwFbynSyYkK+FFGWGiUeQ== 123456\n"
NISTP521_PUB = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACwwC/dqTRtKGsovblIRCkgvfuElot4ma1Iiz5SsHpmPOoT/f/C+hbHkXzA+NO/IfJ4apWWYogydzHfsoZnMtL7cgBmPpOFRo+sOjlaqr9T6rRfznZqTqmb/EnOhmclvyOI+/i66kb7A+BybMh7jEtz4QQlsYbHDsxfepN7rJ/NZgMcVA== desk@phone\n"
NISTP521_PUB_NO_COMMENT = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACwwC/dqTRtKGsovblIRCkgvfuElot4ma1Iiz5SsHpmPOoT/f/C+hbHkXzA+NO/IfJ4apWWYogydzHfsoZnMtL7cgBmPpOFRo+sOjlaqr9T6rRfznZqTqmb/EnOhmclvyOI+/i66kb7A+BybMh7jEtz4QQlsYbHDsxfepN7rJ/NZgMcVA==\n"
RSA_PUB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCqpNHfX9xOW41kl28wgeZHG/szYBldqflpG8HU8+OCZ6J5++Y4WmuHgl/W6ayrULtUWyKF1y7R0qcd8wf58PFwZMP+tAh3pij1vCSiFWYvhkq9b58smFHyHy8ZbpndKBexErpNygDsduy0ecw2wwqFDYn8EHs3tnuyT0Z99XQVScNzlqlLRAMxbLjyGurFSgqXjket9zkDbX6KhkryxiATGQql0inJqio2SkPHHYk2fQqlN4dXp/1oHsFrqGf247nDX3uNKnq7F7qTVbGmH3ehUzc9HqdRnUUFzWwTBn/VGU+zeUaEtBRtVewj/iqG0vKlo3LDm5Kp8LEbhGL88UlmBQRPISZYZ8Hm8lwkcOCnzXvf9gupxoXECqYChhbysMz66OqwAEplVHrFBqCFa0tIb6op+hVkHGuFXW8qlSTam/G0jLBJhRlOXduIrzn29mPhhVk11TQxqsVK9ji1RSG9yKaKxEjgS4z/M4GL0NrTUaVOdDXRDo1bfJHlsN5LSoBT0AwueQCgjieZRNAnQ9rPEPBM/5RGUq+vT//uzqOO9bE1iygixbkyRi6E+35wXqlobRDK8JEeGAKIdzA6NITqQXDHFPo1IsmrIbHagyOUSfH1QYRkG0kyIZBPcmjxjcv4UtjNHAVipWVdceS7FoVtnmPprwJf/hgQ7uIsHZ+DZw==\n"
EDDSA_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUC2eRpGLdX6BBudVLfZReqHpsHjnsn5Swlh6TECs2QZFQ== little@laptop\n"

def test_get_ssh_pubkey_nistp256():
    "To test ssh pubkey"
    nistp256_data = _get_cert_data(BASE_TESTSDIR / "files/nistp256.pub")
    pubkey = rjce.get_ssh_pubkey(nistp256_data, "123456")
    assert NISTP256_PUB == pubkey

def test_get_ssh_pubkey_nistp384():
    "To test ssh pubkey"
    nistp256_data = _get_cert_data(BASE_TESTSDIR / "files/nistp384.pub")
    pubkey = rjce.get_ssh_pubkey(nistp256_data, "123456")
    assert NISTP384_PUB == pubkey

def test_get_ssh_pubkey_nistp521():
    "To test ssh pubkey"
    nistp256_data = _get_cert_data(BASE_TESTSDIR / "files/nistp521.pub")
    pubkey = rjce.get_ssh_pubkey(nistp256_data, "desk@phone")
    assert NISTP521_PUB == pubkey

def test_get_ssh_pubkey_nistp521_no_comment():
    "To test ssh pubkey"
    nistp256_data = _get_cert_data(BASE_TESTSDIR / "files/nistp521.pub")
    pubkey = rjce.get_ssh_pubkey(nistp256_data, None)
    assert NISTP521_PUB_NO_COMMENT == pubkey

def test_no_authentication_key():
    rsa_data = _get_cert_data(BASE_TESTSDIR / "files/hellopublic.asc")
    with pytest.raises(rjce.CryptoError):
        pubkey = rjce.get_ssh_pubkey(rsa_data, None)

def test_get_ssh_pubkey_rsa():
    rsa_data = _get_cert_data(BASE_TESTSDIR / "files/store/kushal_updated_key.asc")
    pubkey = rjce.get_ssh_pubkey(rsa_data, None)
    assert RSA_PUB == pubkey

def test_get_ssh_pubkey_eddsa():
    rsa_data = _get_cert_data(BASE_TESTSDIR / "files/cv25519.pub")
    pubkey = rjce.get_ssh_pubkey(rsa_data, "little@laptop")
    assert EDDSA_PUB == pubkey


