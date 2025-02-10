import io
from datetime import datetime
from enum import IntEnum
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

KeyData = Tuple[List[Dict[Any, Any]], str, bool, datetime, datetime, Dict[Any, Any]]

class CryptoError(BaseException): ...
class SameKeyError(BaseException): ...

class TouchMode(IntEnum):
    Off: int
    On: int
    Fixed: int
    Cached: int
    CachedFixed: int

class KeySlot(IntEnum):
    Signature: int
    Encryption: int
    Authentication: int
    Attestation: int

def set_keyslot_touch_policy(
    adminpin: bytes, slot: KeySlot, mode: TouchMode
) -> bool: ...
def get_keyslot_touch_policy(slot: KeySlot) -> TouchMode: ...
def update_subkeys_expiry_in_cert(
    certdata: bytes, fingerprints: List[str], expirytime: int, password: str
) -> bytes: ...
def update_subkeys_expiry_on_card(
    certdata: bytes, fingerprints: List[str], expirytime: int, pin: bytes
) -> bytes: ...
def update_primary_expiry_in_cert(
    certdata: bytes, expirytime: int, password: str
) -> bytes: ...
def update_primary_expiry_on_card(
    certdata: bytes, expirytime: int, pin: bytes
) -> bytes: ...
def revoke_uid_in_cert(certdata: bytes, uid: bytes, password: str) -> bytes: ...
def add_uid_in_cert(certdata: bytes, uid: bytes, password: str) -> bytes: ...
def update_password(certdata: bytes, password: str, newpass: str) -> bytes: ...
def decrypt_bytes_on_card(certdata: bytes, data: bytes, pin: bytes) -> bytes: ...
def decrypt_file_on_card(
    certdata: bytes, filepath: bytes, output: bytes, pin: bytes
) -> bytes: ...
def decrypt_filehandler_on_card(
    certdata: bytes, fh: BinaryIO, output: bytes, pin: bytes
) -> bytes: ...
def reset_yubikey() -> bool: ...
def get_card_details() -> Dict: ...
def change_user_pin(adminpin: bytes, newpin: bytes) -> bool: ...
def change_admin_pin(adminpin: bytes, newadminpin: bytes) -> bool: ...
def parse_cert_bytes(
    certdata: bytes,
    nullpolicy: Optional[bool] = None,
) -> KeyData: ...
def parse_cert_file(
    certfile: str,
    nullpolicy: Optional[bool] = None,
) -> KeyData: ...
def parse_keyring_file(certfile: str) -> List[Tuple[KeyData, bytes]]: ...
def export_keyring_file(certs: List[bytes], keyringfilename: str) -> bool: ...
def set_name(name: bytes, pin: bytes) -> bool: ...
def set_url(url: bytes, pin: bytes) -> bool: ...
def sign_bytes_detached_on_card(certdata: bytes, data: bytes, pin: bytes) -> str: ...
def sign_file_detached_on_card(certdata: bytes, filepath: bytes, pin: bytes) -> str: ...
def certify_key(
    certdata: bytes,
    othercertdata: bytes,
    sig_type: int,
    uids: List[str],
    password: bytes,
    oncard: bool,
) -> bytes: ...
def sign_file_on_card(
    certdata: bytes, filepath: bytes, output: bytes, pin: bytes, cleartext: bool
) -> bool: ...
def sign_bytes_on_card(
    certdata: bytes, data: bytes, pin: bytes, cleartext: bool
) -> bytes: ...
def merge_keys(certdata: bytes, newcertdata: bytes, force: bool) -> bytes: ...
def file_encrypted_for(filepath: str) -> List[str]: ...
def bytes_encrypted_for(messagedata: bytes) -> List[str]: ...
def get_pub_key(certdata: bytes) -> str: ...
def upload_primary_to_smartcard(
    certdata: bytes, pin: bytes, password: str, whichslot: int
) -> bool: ...
def upload_to_smartcard(
    certdata: bytes, pin: bytes, password: str, whichkeys: int
) -> bool: ...
def get_signing_pubkey(certdata: bytes) -> Dict: ...
def get_ssh_pubkey(certdata: bytes, comment: Optional[str]) -> str: ...
def create_key(
    password: str,
    userids: List[str],
    cipher: str,
    creation: int,
    expiration: int,
    subkeys_expiration: bool,
    whichkeys: int,
    can_primary_sign: bool,
    can_primary_expire: bool,
) -> Tuple[str, str, str]: ...
def encrypt_filehandler_to_file(
    publickeys: List[bytes], fh: io.TextIOWrapper, output: bytes, armor: Optional[bool]
) -> bool: ...
def encrypt_bytes_to_file(
    publickeys: List[bytes], data: bytes, output: bytes, armor: Optional[bool]
) -> bool: ...
def encrypt_bytes_to_bytes(
    publickeys: List[bytes], data: bytes, armor: Optional[bool]
) -> bool: ...
def encrypt_file_internal(
    publickeys: List[List[bytes]], filepath: bytes, output: bytes, armor: Optional[bool]
) -> bytes: ...
def is_smartcard_connected() -> bool: ...
def get_card_version() -> tuple[int, int, int]: ...
def enable_otp_usb() -> bool: ...
def disable_otp_usb() -> bool: ...
def get_key_cipher_details(certdata: bytes) -> List[tuple[str, str, int]]: ...

class Johnny:
    def __init__(self, certdata: bytes) -> Johnny: ...
    def encrypt_bytes(self, data: bytes, armor: Optional[bool]) -> bytes: ...
    def decrypt_bytes(self, data: bytes, password: str) -> bytes: ...
    def encrypt_file(
        self, filepath: bytes, output: bytes, armor: Optional[bool]
    ) -> bool: ...
    def decrypt_file(self, filepath: bytes, output: bytes, password: str) -> bool: ...
    def decrypt_filehandler(
        self, fh: BinaryIO, output: bytes, password: str
    ) -> bool: ...
    def sign_bytes(self, data: bytes, password: str, cleartext: bool) -> bytes: ...
    def sign_file(
        self, inputpath: bytes, output: bytes, password: str, cleartext: bool
    ) -> bool: ...
    def sign_bytes_detached(self, data: bytes, password: str) -> str: ...
    def sign_file_detached(self, filepath: bytes, password: str) -> str: ...
    def verify_bytes_detached(self, data: bytes, sig: bytes) -> bool: ...
    def verify_file_detached(self, filepath: bytes, sig: bytes) -> bool: ...
    def verify_bytes(self, data: bytes) -> bool: ...
    def verify_and_extract_bytes(self, data: bytes) -> bytes: ...
    def verify_file(self, filepath: bytes) -> bool: ...
    def verify_and_extract_file(self, filepath: bytes, output: bytes) -> bool: ...
