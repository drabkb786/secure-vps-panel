"""Root-private, authenticated encryption for owner-requested SSH sharing.

OpenSSL CMS uses AES-256-GCM and RSA-OAEP; passwords only enter subprocess
stdin. The encrypted record is bound to the account identity and current
shadow entry, so external password changes invalidate an old share secret.
"""
import base64
import ctypes
import ctypes.util
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading

from common import BASE_DIR, ValidationError, atomic_write_json, validate_ssh_password
from account_policy import ssh_id

DIRECTORY = BASE_DIR / "ssh-share"
SHADOW = Path("/etc/shadow")
OWNER = 0
OPENSSL = "/usr/bin/openssl"
CRYPT_LOCK = threading.Lock()


def private(path, directory=False):
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != OWNER or info.st_mode & 0o077:
        raise ValidationError("SSH share vault has unsafe ownership or permissions")


def shadow(username):
    for line in SHADOW.read_text().splitlines():
        fields = line.split(":")
        if fields[0] == username and len(fields) > 1:
            return fields[1]
    raise ValidationError("SSH system password entry is missing")


def matches(password, encoded):
    # Python 3.13+ removed crypt; libcrypt remains the OS password verifier.
    if not encoded or encoded.startswith(("!", "*")):
        return False
    library = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
    library.crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    library.crypt.restype = ctypes.c_char_p
    with CRYPT_LOCK:
        result = library.crypt(password.encode(), encoded.encode())
        return bool(result and hmac.compare_digest(result, encoded.encode()))


def run(args, data=None):
    result = subprocess.run([OPENSSL, *args], input=data, capture_output=True, timeout=30)
    if result.returncode:
        # Never surface stdin, decrypted output or provider diagnostics as logs.
        raise ValidationError("SSH share encryption failed; existing vault data was preserved")
    return result.stdout


def record_path(account):
    identity = hashlib.sha256(ssh_id(account).encode()).hexdigest()
    return DIRECTORY / (identity + ".json")


def keys(create=False):
    pair = DIRECTORY / "keys"
    if not pair.exists():
        if not create or any(DIRECTORY.glob("*.json")):
            raise ValidationError("SSH share key is missing; restore the private vault backup")
        stage = Path(tempfile.mkdtemp(prefix=".keys-", dir=DIRECTORY))
        try:
            run(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "36500",
                 "-subj", "/CN=NOWAY private SSH share", "-keyout", str(stage / "key.pem"),
                 "-out", str(stage / "cert.pem")])
            for path in stage.iterdir():
                path.chmod(0o600)
            stage.rename(pair)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    private(pair, True)
    key, cert = pair / "key.pem", pair / "cert.pem"
    try:
        private(key); private(cert)
    except FileNotFoundError as exc:
        raise ValidationError("SSH share key is missing; restore the private vault backup") from exc
    return key, cert


def save(account, password):
    password = validate_ssh_password(password)
    encoded = shadow(account["username"])
    if not matches(password, encoded):
        raise ValidationError("That is not this SSH account's current password")
    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(DIRECTORY, True)
    lock = os.open(DIRECTORY / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private(DIRECTORY / ".lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        _, cert = keys(create=True)
        payload = json.dumps({"identity": ssh_id(account), "password": password,
                              "shadow_tag": hashlib.sha256(encoded.encode()).hexdigest()}).encode()
        encrypted = run(["cms", "-encrypt", "-binary", "-outform", "DER", "-aes-256-gcm",
                         "-recip", str(cert), "-keyopt", "rsa_padding_mode:oaep",
                         "-keyopt", "rsa_oaep_md:sha256"], payload)
        atomic_write_json(record_path(account), {"schema": 1, "cms": base64.b64encode(encrypted).decode()})
    finally:
        os.close(lock)


def load(account):
    path = record_path(account)
    if not DIRECTORY.exists():
        return None
    private(DIRECTORY, True)
    if not path.exists():
        return None
    private(path)
    key, cert = keys()
    try:
        record = json.loads(path.read_text())
        if record.get("schema") != 1 or path.stat().st_size > 16384:
            raise ValueError("Invalid record")
        data = run(["cms", "-decrypt", "-binary", "-inform", "DER", "-recip", str(cert),
                    "-inkey", str(key)], base64.b64decode(record["cms"], validate=True))
        content = json.loads(data)
        if content["identity"] != ssh_id(account):
            raise ValueError("Account identity changed")
        if content["shadow_tag"] != hashlib.sha256(shadow(account["username"]).encode()).hexdigest():
            return None
        return validate_ssh_password(content["password"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError("SSH share record is invalid; restore its private backup") from exc


def forget(account):
    if DIRECTORY.exists():
        private(DIRECTORY, True)
        record_path(account).unlink(missing_ok=True)
