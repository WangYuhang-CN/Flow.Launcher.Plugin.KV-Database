from __future__ import annotations

import base64
import ctypes
import hashlib
import secrets
from ctypes import wintypes

DPAPI_ENTROPY = b"Flow.Launcher.Plugin.KV-Database:data-key:v1"
RECOVERY_KDF_ITERATIONS = 200_000
RECOVERY_KEY_BYTES = 20
AES_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16


class CryptoError(Exception):
    """Raised when encryption, decryption, or key wrapping fails."""


class RecoveryKeyError(CryptoError):
    """Raised when a recovery key is missing or invalid."""


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def generate_recovery_key() -> str:
    body = base64.b32encode(random_bytes(RECOVERY_KEY_BYTES)).decode("ascii").rstrip("=")
    return _format_recovery_key_body(body)


def normalize_recovery_key(recovery_key: str) -> str:
    compact = "".join(char for char in recovery_key.upper() if char.isalnum())
    if compact.startswith("KVDB"):
        compact = compact[4:]
    if len(compact) != 32:
        raise RecoveryKeyError("Recovery key has an invalid length.")

    try:
        base64.b32decode(compact, casefold=True)
    except Exception as exc:
        raise RecoveryKeyError("Recovery key contains invalid characters.") from exc

    return _format_recovery_key_body(compact)


def derive_recovery_key(recovery_key: str, salt: bytes) -> bytes:
    canonical_key = normalize_recovery_key(recovery_key)
    return hashlib.pbkdf2_hmac(
        "sha256",
        canonical_key.encode("ascii"),
        salt,
        RECOVERY_KDF_ITERATIONS,
        dklen=AES_KEY_BYTES,
    )


def dpapi_protect(data: bytes) -> bytes:
    return _crypt_protect_data(data, DPAPI_ENTROPY)


def dpapi_unprotect(data: bytes) -> bytes:
    return _crypt_unprotect_data(data, DPAPI_ENTROPY)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = random_bytes(AES_GCM_NONCE_BYTES)
    ciphertext, tag = _bcrypt_aes_gcm_crypt(
        key=key,
        data=plaintext,
        nonce=nonce,
        aad=aad,
        tag=None,
        encrypt=True,
    )
    return nonce, ciphertext + tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, encrypted: bytes, aad: bytes = b"") -> bytes:
    if len(encrypted) < AES_GCM_TAG_BYTES:
        raise CryptoError("Encrypted value is too short.")

    ciphertext = encrypted[:-AES_GCM_TAG_BYTES]
    tag = encrypted[-AES_GCM_TAG_BYTES:]
    plaintext, _ = _bcrypt_aes_gcm_crypt(
        key=key,
        data=ciphertext,
        nonce=nonce,
        aad=aad,
        tag=tag,
        encrypt=False,
    )
    return plaintext


def _format_recovery_key_body(body: str) -> str:
    groups = [body[index : index + 4] for index in range(0, len(body), 4)]
    return "KVDB-" + "-".join(groups)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _bytes_from_blob(blob: DATA_BLOB) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _crypt_protect_data(data: bytes, entropy: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    data_blob, data_buffer = _blob_from_bytes(data)
    entropy_blob, entropy_buffer = _blob_from_bytes(entropy)
    output_blob = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(data_blob),
        "KV Database data key",
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,
        ctypes.byref(output_blob),
    ):
        raise CryptoError(f"CryptProtectData failed: {ctypes.get_last_error()}")

    try:
        return _bytes_from_blob(output_blob)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        _keepalive(data_buffer, entropy_buffer)


def _crypt_unprotect_data(data: bytes, entropy: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    data_blob, data_buffer = _blob_from_bytes(data)
    entropy_blob, entropy_buffer = _blob_from_bytes(entropy)
    output_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(data_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,
        ctypes.byref(output_blob),
    ):
        raise CryptoError(f"CryptUnprotectData failed: {ctypes.get_last_error()}")

    try:
        return _bytes_from_blob(output_blob)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        _keepalive(data_buffer, entropy_buffer)


class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwInfoVersion", wintypes.ULONG),
        ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbNonce", wintypes.ULONG),
        ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbAuthData", wintypes.ULONG),
        ("pbTag", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbTag", wintypes.ULONG),
        ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbMacContext", wintypes.ULONG),
        ("cbAAD", wintypes.ULONG),
        ("cbData", ctypes.c_ulonglong),
        ("dwFlags", wintypes.ULONG),
    ]


def _bcrypt_aes_gcm_crypt(
    key: bytes,
    data: bytes,
    nonce: bytes,
    aad: bytes,
    tag: bytes | None,
    encrypt: bool,
) -> tuple[bytes, bytes]:
    if len(key) not in (16, 24, 32):
        raise CryptoError("AES key has an invalid length.")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise CryptoError("AES-GCM nonce has an invalid length.")
    if tag is not None and len(tag) != AES_GCM_TAG_BYTES:
        raise CryptoError("AES-GCM tag has an invalid length.")

    bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
    _set_bcrypt_prototypes(bcrypt)
    h_alg = wintypes.HANDLE()
    h_key = wintypes.HANDLE()
    key_object = None

    try:
        _nt_success(
            bcrypt.BCryptOpenAlgorithmProvider(
                ctypes.byref(h_alg),
                ctypes.c_wchar_p("AES"),
                None,
                0,
            ),
            "BCryptOpenAlgorithmProvider",
        )
        chaining_mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        _nt_success(
            bcrypt.BCryptSetProperty(
                h_alg,
                ctypes.c_wchar_p("ChainingMode"),
                ctypes.cast(chaining_mode, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.sizeof(chaining_mode),
                0,
            ),
            "BCryptSetProperty(ChainingModeGCM)",
        )

        object_length = _bcrypt_get_ulong_property(bcrypt, h_alg, "ObjectLength")
        key_object = ctypes.create_string_buffer(object_length)
        key_buffer = ctypes.create_string_buffer(key, len(key))
        _nt_success(
            bcrypt.BCryptGenerateSymmetricKey(
                h_alg,
                ctypes.byref(h_key),
                ctypes.cast(key_object, ctypes.POINTER(ctypes.c_ubyte)),
                object_length,
                ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_ubyte)),
                len(key),
                0,
            ),
            "BCryptGenerateSymmetricKey",
        )

        nonce_buffer = ctypes.create_string_buffer(nonce, len(nonce))
        aad_buffer = ctypes.create_string_buffer(aad, len(aad)) if aad else None
        tag_buffer = (
            ctypes.create_string_buffer(AES_GCM_TAG_BYTES)
            if encrypt
            else ctypes.create_string_buffer(tag, len(tag))
        )
        mac_context = ctypes.create_string_buffer(AES_GCM_TAG_BYTES)
        info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(
            ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
            1,
            ctypes.cast(nonce_buffer, ctypes.POINTER(ctypes.c_ubyte)),
            len(nonce),
            ctypes.cast(aad_buffer, ctypes.POINTER(ctypes.c_ubyte)) if aad_buffer else None,
            len(aad),
            ctypes.cast(tag_buffer, ctypes.POINTER(ctypes.c_ubyte)),
            AES_GCM_TAG_BYTES,
            ctypes.cast(mac_context, ctypes.POINTER(ctypes.c_ubyte)),
            AES_GCM_TAG_BYTES,
            0,
            0,
            0,
        )

        input_buffer = ctypes.create_string_buffer(data, len(data)) if data else None
        output_buffer = ctypes.create_string_buffer(len(data)) if data else None
        output_length = wintypes.ULONG()
        crypt_func = bcrypt.BCryptEncrypt if encrypt else bcrypt.BCryptDecrypt

        _nt_success(
            crypt_func(
                h_key,
                ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)) if input_buffer else None,
                len(data),
                ctypes.byref(info),
                None,
                0,
                ctypes.cast(output_buffer, ctypes.POINTER(ctypes.c_ubyte)) if output_buffer else None,
                len(data),
                ctypes.byref(output_length),
                0,
            ),
            "BCryptEncrypt" if encrypt else "BCryptDecrypt",
        )

        result = ctypes.string_at(output_buffer, output_length.value) if output_buffer else b""
        return result, ctypes.string_at(tag_buffer, AES_GCM_TAG_BYTES)
    finally:
        if h_key:
            bcrypt.BCryptDestroyKey(h_key)
        if h_alg:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
        _keepalive(key_object)


def _bcrypt_get_ulong_property(bcrypt, handle, property_name: str) -> int:
    output = wintypes.ULONG()
    output_length = wintypes.ULONG()
    _nt_success(
        bcrypt.BCryptGetProperty(
            handle,
            ctypes.c_wchar_p(property_name),
            ctypes.cast(ctypes.byref(output), ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.sizeof(output),
            ctypes.byref(output_length),
            0,
        ),
        f"BCryptGetProperty({property_name})",
    )
    return output.value


def _set_bcrypt_prototypes(bcrypt) -> None:
    ntstatus = ctypes.c_long
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.ULONG,
    ]
    bcrypt.BCryptOpenAlgorithmProvider.restype = ntstatus
    bcrypt.BCryptSetProperty.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    bcrypt.BCryptSetProperty.restype = ntstatus
    bcrypt.BCryptGetProperty.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.ULONG,
    ]
    bcrypt.BCryptGetProperty.restype = ntstatus
    bcrypt.BCryptGenerateSymmetricKey.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    bcrypt.BCryptGenerateSymmetricKey.restype = ntstatus

    crypt_args = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.ULONG,
    ]
    bcrypt.BCryptEncrypt.argtypes = crypt_args
    bcrypt.BCryptEncrypt.restype = ntstatus
    bcrypt.BCryptDecrypt.argtypes = crypt_args
    bcrypt.BCryptDecrypt.restype = ntstatus
    bcrypt.BCryptDestroyKey.argtypes = [wintypes.HANDLE]
    bcrypt.BCryptDestroyKey.restype = ntstatus
    bcrypt.BCryptCloseAlgorithmProvider.argtypes = [wintypes.HANDLE, wintypes.ULONG]
    bcrypt.BCryptCloseAlgorithmProvider.restype = ntstatus


def _nt_success(status: int, operation: str) -> None:
    if status < 0:
        raise CryptoError(f"{operation} failed: 0x{status & 0xFFFFFFFF:08X}")


def _keepalive(*_values) -> None:
    return None
