"""
USB Locker Pro
==============

SECURITY DESIGN
----------------
- AES-256-GCM authenticated encryption for file contents.
- A random 256-bit master key per vault encrypts the files - never a
  password directly.
- The master key is key-wrapped once per password: one slot for your main
  password, one slot per recovery key. Each slot has its own random salt
  and its own Argon2id-derived key. Any single correct password/key
  independently recovers the same master key.
- Random nonce per encrypted chunk; associated data binds each chunk to its
  file path, chunk index, and plaintext length.
- No password or recovery key is stored in plaintext, anywhere.
"""

import os
import sys
import json
import base64
import secrets
import shutil
import threading
import time
import errno
import atexit
import signal
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

APP_NAME = "USB Locker Pro"
VAULT_DIR_NAME = ".USBLocker"
VAULT_FILE = "vault.usbvl"
UNLOCKED_DIR_NAME = "Unlocked"
LOCATION_MARKER_NAME = "working_location.txt"
FORMAT = b"USBVL04"
OLD_FORMAT = b"USBVL03"          # still readable, so old vaults aren't stranded
OLD_HEADER_RESERVED = 16384      # reserved-header size used by USBVL03 vaults
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
CHUNK_SIZE = 4 * 1024 * 1024     # 4 MiB - fewer, bigger writes than the old 1 MiB
HEADER_RESERVED = 4 * 1024 * 1024  # v4 header no longer scales with chunk count,
                                    # only with file COUNT, so this is very generous
RECOVERY_MAX = 5
MIN_PASSWORD_LEN = 12
WRAP_AAD = b"usb-locker-pro-keywrap-v1"
EXCLUDED_TOP_NAMES = {VAULT_DIR_NAME, UNLOCKED_DIR_NAME}
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no ambiguous chars (I,O,0,1)
LOCKOUT_THRESHOLD = 3          # failed attempts before a cooldown kicks in
LOCKOUT_BASE_SECONDS = 20      # first cooldown length
LOCKOUT_MAX_SECONDS = 300      # cooldown never grows past this
DRIVE_POLL_MS = 2000           # how often to check the USB is still present
DRIVE_LOST_CONFIRM_SECONDS = 6  # must be missing this long before we act - filters blips


def human_readable(num_bytes):
    n = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024


def human_readable_time(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, s = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {s}s"
    hours, m = divmod(minutes, 60)
    return f"{hours}h {m}m"


def required_unlock_space(header):
    """Total plaintext bytes the vault will need on disk once decrypted,
    plus a small safety margin for filesystem overhead."""
    total = sum(x.get("size", 0) for x in header.get("files", []))
    return int(total * 1.02) + 5 * 1024 * 1024  # +2% and +5 MiB slack


def free_space_at(path):
    try:
        return shutil.disk_usage(str(path)).free
    except Exception:
        return None


def write_location_marker(drive, working_path):
    """Records where the currently-unlocked working folder actually lives -
    it might not be on the USB itself anymore now that you can choose a
    different location. This is what lets crash-recovery find it again on
    the next launch, wherever it is."""
    try:
        marker = drive / VAULT_DIR_NAME / LOCATION_MARKER_NAME
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(working_path), encoding="utf-8")
    except Exception:
        pass  # non-critical - worst case, crash recovery falls back to the USB


def read_location_marker(drive):
    """Returns the Path last recorded by write_location_marker, or the
    default drive/Unlocked location if no marker exists (normal case, or an
    older vault from before this existed)."""
    marker = drive / VAULT_DIR_NAME / LOCATION_MARKER_NAME
    try:
        raw = marker.read_text(encoding="utf-8").strip()
        if raw:
            return Path(raw)
    except Exception:
        pass
    return drive / UNLOCKED_DIR_NAME


def clear_location_marker(drive):
    try:
        (drive / VAULT_DIR_NAME / LOCATION_MARKER_NAME).unlink(missing_ok=True)
    except Exception:
        pass


def password_strength(password):
    """Very rough, dependency-free strength estimate (not a real entropy
    model) - just enough to nudge someone away from an obviously weak
    passphrase at vault-creation time. Returns (label, tips)."""
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    length_score = min(len(password) / 20, 1.0)  # saturates at 20 chars
    score = length_score * 0.6 + (classes / 4) * 0.4
    if score < 0.4:
        label = "Weak"
    elif score < 0.7:
        label = "Okay"
    else:
        label = "Strong"
    tips = []
    if len(password) < 16:
        tips.append("Longer is better - consider 16+ characters, e.g. a short passphrase.")
    if classes < 3:
        tips.append("Mix in uppercase, digits, and symbols.")
    return label, tips


# --------------------------------------------------------------------------
# Encoding helpers
# --------------------------------------------------------------------------

def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s.encode("ascii"))


# --------------------------------------------------------------------------
# Key derivation + multi-password key wrapping
# --------------------------------------------------------------------------

def derive_key(password, salt):
    """Argon2id: memory-hard password KDF."""
    return hash_secret_raw(
        password.encode("utf-8"), salt,
        time_cost=3, memory_cost=128 * 1024, parallelism=2,
        hash_len=KEY_LEN, type=Type.ID,
    )


def wrap_key(password, master_key, label):
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_LEN)
    wrapped = AESGCM(kek).encrypt(nonce, master_key, WRAP_AAD)
    return {"label": label, "salt": b64e(salt), "nonce": b64e(nonce), "wrapped": b64e(wrapped)}


def try_unwrap(password, entry):
    try:
        salt = b64d(entry["salt"])
        nonce = b64d(entry["nonce"])
        wrapped = b64d(entry["wrapped"])
        kek = derive_key(password, salt)
        return AESGCM(kek).decrypt(nonce, wrapped, WRAP_AAD)
    except Exception:
        return None


def unwrap_master_key(password, key_entries):
    for entry in key_entries:
        mk = try_unwrap(password, entry)
        if mk is not None:
            return mk, entry
    return None, None


def generate_recovery_key():
    groups = ["".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(5)) for _ in range(4)]
    return "-".join(groups)


# --------------------------------------------------------------------------
# Secure delete
# --------------------------------------------------------------------------

def secure_overwrite(path):
    """Overwrites the file's bytes with zeros before deleting it, so a
    normal undelete/recovery tool has nothing readable left to recover -
    unlike a regular delete, which just frees up the space while the actual
    data often stays on disk until something else overwrites it. Not a
    guarantee on SSD/flash, since the controller can silently remap blocks
    behind the scenes."""
    try:
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as f:
            remaining = size
            block = b"\x00" * (1024 * 1024)
            while remaining:
                n = min(remaining, len(block))
                f.write(block[:n])
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
        path.unlink(missing_ok=True)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def secure_wipe_folder(folder: Path, progress=None, strict=False):
    """Overwrites then deletes everything under folder.

    Windows keeps a handle on files that are open in Explorer's preview
    pane, a media player, an editor, etc., and those deletions fail. The
    old version swallowed every such failure silently, which meant
    plaintext could quietly survive a "securely deleted" message. Now the
    failures are collected, retried, and reported.

    strict=True raises if anything survived, so a caller that promised the
    user a wipe can tell them the truth instead."""
    folder = Path(folder)
    if not folder.exists():
        return []

    files = [x for x in folder.rglob("*") if x.is_file()]
    total = len(files) or 1
    failed = []
    for i, p in enumerate(files, 1):
        ok = False
        for attempt in range(3):
            try:
                secure_overwrite(p)
                ok = not p.exists()
                if ok:
                    break
            except Exception:
                pass
            time.sleep(0.4)  # give whatever holds the handle a moment
        if not ok:
            failed.append(p)
        if progress:
            progress(i, total)

    for d in sorted((p for p in folder.rglob("*") if p.is_dir()), key=lambda x: -len(str(x))):
        try:
            d.rmdir()
        except OSError:
            pass
    try:
        folder.rmdir()
    except OSError:
        pass

    if failed and strict:
        shown = "\n".join(f"  - {p}" for p in failed[:8])
        more = f"\n  ...and {len(failed) - 8} more" if len(failed) > 8 else ""
        raise ValueError(
            f"{len(failed)} file(s) could NOT be erased because another program is "
            f"still using them:\n{shown}{more}\n\n"
            "These files are still UNENCRYPTED on disk. Close File Explorer windows "
            "showing that folder (including the preview pane), plus any media player "
            "or editor with those files open, then use 'Securely Wipe a Folder...' "
            "on it."
        )
    return failed


# --------------------------------------------------------------------------
# Drive helpers
# --------------------------------------------------------------------------

def drive_list():
    if os.name != "nt":
        return []
    result = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        p = Path(f"{letter}:\\")
        if p.exists():
            result.append(p)
    return result


DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR, DRIVE_REMOVABLE = 0, 1, 2
DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM, DRIVE_RAMDISK = 3, 4, 5, 6
_DRIVE_TYPE_LABELS = {
    DRIVE_UNKNOWN: "unknown", DRIVE_NO_ROOT_DIR: "unavailable",
    DRIVE_REMOVABLE: "removable", DRIVE_FIXED: "fixed internal disk",
    DRIVE_REMOTE: "network drive", DRIVE_CDROM: "CD/DVD drive",
    DRIVE_RAMDISK: "RAM disk",
}


def get_drive_type(drive):
    if os.name != "nt":
        return DRIVE_UNKNOWN
    try:
        import ctypes
        return ctypes.windll.kernel32.GetDriveTypeW(str(drive))
    except Exception:
        return DRIVE_UNKNOWN


def drive_type_label(drive):
    return _DRIVE_TYPE_LABELS.get(get_drive_type(drive), "unknown")


def is_probably_removable(drive):
    return get_drive_type(drive) == DRIVE_REMOVABLE


# --------------------------------------------------------------------------
# Free space checking
# --------------------------------------------------------------------------

FREE_SPACE_MARGIN_BYTES = 20 * 1024 * 1024  # cushion for filesystem overhead


def get_free_bytes(path):
    try:
        return shutil.disk_usage(str(path)).free
    except Exception:
        return None


def required_bytes_for_unlock(header):
    """Space needed on disk to hold the DECRYPTED plaintext, which is
    exactly the original file sizes - AES-GCM's 16-byte tag only exists in
    the ciphertext inside the vault, never in the decrypted output files."""
    files = header.get("files", [])
    return sum(x.get("size", 0) for x in files)


def format_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def is_system_drive(drive):
    system_drive = os.environ.get("SystemDrive", "C:")
    try:
        return str(drive).rstrip("\\").rstrip("/").lower() == f"{system_drive}\\".rstrip("\\").lower()
    except Exception:
        return str(drive).upper().startswith("C:")


def detect_running_drive():
    try:
        exe_path = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
        d = Path(exe_path.drive + "\\")
        if d.exists():
            return d
    except Exception:
        pass
    return None


def validate_source(source, vault_path):
    source = Path(source).resolve()
    vault_path = Path(vault_path).resolve()
    if source == vault_path or vault_path.is_relative_to(source):
        raise ValueError("The source folder cannot contain the USB vault.")


def safe_join(destination: Path, rel_path: str) -> Path:
    destination = Path(destination).resolve()
    if not rel_path or Path(rel_path).is_absolute():
        raise ValueError(f"Vault entry has an unsafe path and was rejected: {rel_path!r}")
    candidate = (destination / rel_path).resolve()
    try:
        candidate.relative_to(destination)
    except ValueError:
        raise ValueError(f"Vault entry has an unsafe path and was rejected: {rel_path!r}")
    return candidate


# --------------------------------------------------------------------------
# Vault header I/O
# --------------------------------------------------------------------------

def read_vault_header(vault_path):
    vault_path = Path(vault_path)
    with vault_path.open("rb") as f:
        magic = f.read(len(FORMAT))
        if magic == FORMAT:
            reserved = HEADER_RESERVED
        elif magic == OLD_FORMAT:
            reserved = OLD_HEADER_RESERVED
        else:
            raise ValueError(
                "This is not a valid USB Locker Pro vault (or it was created by an "
                "incompatible older version)."
            )
        header_raw = f.read(reserved).rstrip(b" ")
        try:
            header = json.loads(header_raw.decode("utf-8"))
            if "files" not in header or "keys" not in header:
                raise ValueError()
        except Exception:
            raise ValueError("The vault header is corrupted or unreadable.")
    # Internal bookkeeping only (not written back by _write_vault, which
    # always produces a fresh current-format header) - tells
    # rewrite_vault_header() where the header block actually ends for THIS
    # file, so editing an older vault's keys in place can't corrupt it.
    header["_magic"] = magic.decode("ascii")
    header["_reserved"] = reserved
    return header


def rewrite_vault_header(vault_path, header):
    """Overwrites only the fixed-size header block in place. File chunk data
    doesn't move, so this is fast even on a large vault - used when rotating
    a password via a recovery key. Uses whichever reserved-header size THIS
    vault was actually written with (old or new format), so it never
    corrupts the start of the file data that follows."""
    reserved = header.get("_reserved", HEADER_RESERVED)
    to_write = {k: v for k, v in header.items() if not k.startswith("_")}
    header_bytes = json.dumps(to_write, separators=(",", ":")).encode()
    if len(header_bytes) > reserved:
        raise ValueError("Vault metadata is too large to update in place.")
    with Path(vault_path).open("r+b") as f:
        f.seek(len(FORMAT))  # both magics are the same length
        f.write(header_bytes.ljust(reserved, b" "))
        f.flush()
        os.fsync(f.fileno())


def check_password(vault_path, password):
    """Tries `password` against every key slot (main + recovery). Fails fast
    with a clear error if none match."""
    header = read_vault_header(vault_path)
    key_entries = header.get("keys", [])
    if not key_entries:
        raise ValueError("This vault's key data is missing or corrupted.")
    master_key, _entry = unwrap_master_key(password, key_entries)
    if master_key is None:
        raise ValueError("Incorrect password.")
    return master_key, header


def rotate_main_password(vault_path, header, master_key, used_recovery_entry, new_password):
    """Replaces the main-password slot with one wrapping the SAME master_key
    under new_password, and removes (consumes) the recovery key that was
    used to authorize this. All other recovery keys are untouched. File
    data is never touched - only the small header changes."""
    key_entries = header.get("keys", [])
    new_entries = [e for e in key_entries
                   if e is not used_recovery_entry and e.get("label") != "main"]
    new_entries.insert(0, wrap_key(new_password, master_key, "main"))
    header["keys"] = new_entries
    rewrite_vault_header(vault_path, header)


def count_recovery_keys(header):
    """How many unused recovery-key slots this vault currently has."""
    return sum(1 for e in header.get("keys", []) if e.get("label", "").startswith("recovery"))


def replace_recovery_keys(vault_path, header, master_key, new_keys):
    """Drops every existing recovery slot and replaces it with fresh ones
    wrapping the SAME master_key. Used after a recovery key is spent, or
    whenever the user wants to top back up to a full set. The main-password
    slot is untouched; file data is never touched."""
    key_entries = header.get("keys", [])
    new_entries = [e for e in key_entries if not e.get("label", "").startswith("recovery")]
    for i, k in enumerate(new_keys, 1):
        new_entries.append(wrap_key(k, master_key, f"recovery{i}"))
    header["keys"] = new_entries
    rewrite_vault_header(vault_path, header)


# --------------------------------------------------------------------------
# Core encrypt / decrypt
# --------------------------------------------------------------------------

def _collect_files(source):
    source = Path(source)
    files = []
    for p in source.rglob("*"):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(source).parts
        if rel_parts and rel_parts[0] in EXCLUDED_TOP_NAMES:
            continue
        files.append((p, "/".join(rel_parts)))
    return files


def _estimate_header_bytes(key_entries, files):
    """Fast, rough upper-bound estimate of the JSON header size for the NEW
    (v4) format, used to fail in under a second on an absurd file count
    instead of after hours of encrypting. The real, exact check still runs
    at the end of _write_vault as a safety net."""
    per_key = 220
    per_file = 60  # {"path":"...","size":123456789} plus JSON punctuation
    path_chars = sum(len(rel) for _, rel in files)
    return 300 + per_key * len(key_entries) + per_file * len(files) + path_chars


def _iter_chunk_plain_lens(size, chunk_size):
    """Yields the plaintext length of each chunk for a file of `size` bytes,
    in order - matching exactly how _write_vault split it, so decrypt/verify
    can reconstruct the same chunk boundaries without storing them
    explicitly in the header."""
    if size <= 0:
        return
    remaining = size
    while remaining > 0:
        n = min(chunk_size, remaining)
        yield n
        remaining -= n


SYNC_EVERY_BYTES = 48 * 1024 * 1024  # force a real flush to the USB this often


def copy_with_progress(src, dst, progress=None):
    """Chunked file copy that actually reports progress and periodically
    fsyncs. shutil.copy2() reports NOTHING, so a multi-GB copy from a fast
    local disk onto a slow USB drive looked exactly like a frozen app -
    which is what led people to force-close mid-copy and strand a partial
    .tmp file on the drive. Never use a silent copy for the USB step."""
    src = Path(src)
    dst = Path(dst)
    total = src.stat().st_size or 1
    done = 0
    since_sync = 0
    with src.open("rb") as fin, dst.open("wb") as fout:
        while True:
            buf = fin.read(CHUNK_SIZE)
            if not buf:
                break
            fout.write(buf)
            done += len(buf)
            since_sync += len(buf)
            if since_sync >= SYNC_EVERY_BYTES:
                fout.flush()
                os.fsync(fout.fileno())
                since_sync = 0
            if progress:
                progress(done, total)
        fout.flush()
        os.fsync(fout.fileno())
    shutil.copystat(src, dst)


def _write_vault(vault_path, key_entries, files, master_key, progress=None):
    """Shared writer used both by first-time encryption and by 'save on
    lock' re-encryption. key_entries are written as-is (unchanged).

    Header format (v4): each file entry is just {"path", "size"} - NOT a
    list of every chunk's offset/length. Chunk boundaries are fully
    deterministic from (size, chunk_size), so decrypt/verify recompute them
    instead of storing them. This is what lets the header stay a few KB
    even for tens of thousands of files or huge (30GB+) individual files -
    the old per-chunk-list format could blow past its fixed header budget
    on large data and fail only after fully encrypting everything.

    Periodically calling os.fsync() below forces Windows to actually finish
    writing to the USB drive at regular intervals, instead of silently
    buffering a large write-behind backlog in RAM that then has to catch up
    all at once later. Without this, the progress bar can report an
    impossible speed (faster than any real flash drive) while writes are
    only hitting RAM, then appear to freeze for a long stretch once that
    buffer fills and the real, much slower hardware has to catch up."""
    estimated = _estimate_header_bytes(key_entries, files)
    if estimated > HEADER_RESERVED:
        raise ValueError(
            f"This vault would need roughly {human_readable(estimated)} of header "
            f"space for {len(files)} files, more than the "
            f"{human_readable(HEADER_RESERVED)} budget. Try fewer, larger files "
            f"(e.g. zip a big folder of many small files first)."
        )

    total = sum(p.stat().st_size for p, _ in files) or 1
    done = 0
    since_sync = 0
    vault_path = Path(vault_path)
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    temp = vault_path.with_suffix(".tmp")
    try:
        with temp.open("wb") as out:
            out.write(FORMAT)
            header = {
                "version": 4,
                "chunk_size": CHUNK_SIZE,
                "keys": key_entries,
                "files": [{"path": rel, "size": src.stat().st_size} for src, rel in files],
            }
            header_pos = out.tell()
            out.write(b"0" * HEADER_RESERVED)

            for src, rel in files:
                idx = 0
                with src.open("rb") as f:
                    while True:
                        plain = f.read(CHUNK_SIZE)
                        if not plain:
                            break
                        nonce = secrets.token_bytes(NONCE_LEN)
                        aad = f"{rel}|{idx}|{len(plain)}".encode()
                        cipher = AESGCM(master_key).encrypt(nonce, plain, aad)
                        out.write(nonce)
                        out.write(len(cipher).to_bytes(8, "big"))
                        out.write(cipher)
                        idx += 1
                        done += len(plain)
                        since_sync += len(plain)
                        if since_sync >= SYNC_EVERY_BYTES:
                            out.flush()
                            os.fsync(out.fileno())
                            since_sync = 0
                        if progress:
                            progress(done, total)

            header_bytes = json.dumps(header, separators=(",", ":")).encode()
            if len(header_bytes) > HEADER_RESERVED:
                # Should be caught by the estimate above; this is the exact,
                # authoritative check as a final safety net.
                raise ValueError(
                    f"Vault metadata ({human_readable(len(header_bytes))}) exceeded "
                    f"the {human_readable(HEADER_RESERVED)} header budget for "
                    f"{len(files)} files."
                )
            out.flush()
            out.seek(header_pos)
            out.write(header_bytes.ljust(HEADER_RESERVED, b" "))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, vault_path)
    finally:
        temp.unlink(missing_ok=True)


def encrypt_folder(source, vault_path, main_password, recovery_keys, progress=None):
    source = Path(source)
    vault_path = Path(vault_path)
    validate_source(source, vault_path)
    if len(recovery_keys) > RECOVERY_MAX:
        raise ValueError(f"Too many recovery keys (maximum is {RECOVERY_MAX}).")

    files = _collect_files(source)
    if not files:
        raise ValueError(
            "The selected folder has no files in it (it may be empty, or only "
            "contain empty subfolders). Choose a different folder to encrypt."
        )

    master_key = secrets.token_bytes(KEY_LEN)
    key_entries = [wrap_key(main_password, master_key, "main")]
    for i, k in enumerate(recovery_keys, 1):
        key_entries.append(wrap_key(k, master_key, f"recovery{i}"))

    _write_vault(vault_path, key_entries, files, master_key, progress)
    return master_key


def encrypt_folder_safe(source, vault_path, main_password, recovery_keys,
                         alt_build_dir=None, progress=None, phase=None):
    """Same job as encrypt_folder(), but when alt_build_dir is given, builds
    and fully verifies the new vault THERE first, and only removes any
    existing vault on the destination drive once a good, verified
    replacement already exists - see _swap_build_and_install()."""
    vault_path = Path(vault_path)

    if alt_build_dir is None:
        if phase:
            phase("Encrypting your files...")
        encrypt_folder(source, vault_path, main_password, recovery_keys, progress)
        return

    alt_build_dir = Path(alt_build_dir)
    alt_vault = alt_build_dir / f"USBLockerPro_rebuild_{int(time.time())}.usbvl"
    final_tmp = vault_path.with_suffix(".tmp")

    # encrypt_folder generates the master key internally, so capture it for
    # the verification steps inside the swap.
    captured = {}

    def build(p):
        captured["mk"] = encrypt_folder(source, alt_vault, main_password, recovery_keys, p)

    def say(text):
        if phase:
            phase(text)

    _swap_build_and_install(alt_vault, vault_path, final_tmp, None,
                             build, progress, phase, capture=captured)


def save_folder_into_vault(source_folder, vault_path, master_key, key_entries, progress=None):
    """Re-encrypts whatever is CURRENTLY in source_folder back into the
    vault, reusing the same master key and the same password/recovery-key
    slots. This is what makes the vault mutable: add/edit/delete files in
    the Unlocked folder, then Lock Now calls this to save it.

    This writes the new vault ALONGSIDE the old one (old vault + new vault
    both present until the atomic swap at the end), which needs roughly
    2x the data size in free space. Use save_folder_into_vault_safe()
    instead when the drive might be too full for that."""
    files = _collect_files(source_folder)
    if not files:
        raise ValueError(
            "The unlocked folder is empty. Lock Now refuses to save an empty vault "
            "so you don't accidentally erase everything - add at least one file "
            "back, or use Reset App if you really want to erase the vault."
        )
    _write_vault(vault_path, key_entries, files, master_key, progress)


def save_folder_into_vault_safe(source_folder, vault_path, master_key, key_entries,
                                 alt_build_dir=None, progress=None, phase=None,
                                 wipe_source_after_verify=False):
    """Same job as save_folder_into_vault(), but when alt_build_dir is given,
    builds and fully verifies the new vault THERE first - never touching the
    old vault on the (possibly nearly-full) USB drive until a good, verified
    replacement already exists. Only then does it delete the old vault and
    move the new one into place. This is what makes locking possible even
    when the USB doesn't have room for old-vault + new-vault + the unlocked
    folder all at once.

    wipe_source_after_verify securely erases source_folder at the safe point
    (new vault built AND verified, old vault not yet touched). Doing it there
    rather than at the very end frees that space before the USB copy runs,
    which is often exactly what makes the copy fit.

    IMPORTANT: a file that can't be wiped (commonly because this app's own
    auto-opened Explorer window still has a handle on it) must NEVER abort
    the save - your data is already safely verified inside the new vault at
    that point, so a stuck plaintext file is a cleanup problem, not a save
    failure. This returns the list of files that could not be wiped (empty
    if none, or if wipe_source_after_verify was False) so the caller can
    warn about them without treating the save itself as failed."""
    files = _collect_files(source_folder)
    if not files:
        raise ValueError(
            "The unlocked folder is empty. Lock Now refuses to save an empty vault "
            "so you don't accidentally erase everything - add at least one file "
            "back, or use Reset App if you really want to erase the vault."
        )

    vault_path = Path(vault_path)
    source_folder = Path(source_folder)
    wipe_failures = []

    if alt_build_dir is None:
        if phase:
            phase("Encrypting your files...")
        _write_vault(vault_path, key_entries, files, master_key, progress)
        if wipe_source_after_verify:
            if phase:
                phase("Securely erasing the unlocked copy...")
            wipe_failures.extend(secure_wipe_folder(source_folder, progress, strict=False))
        return wipe_failures

    def after_verified(say, prog):
        if wipe_source_after_verify:
            say("Securely erasing the unlocked copy (frees space for the copy)...")
            wipe_failures.extend(secure_wipe_folder(source_folder, prog, strict=False))

    alt_build_dir = Path(alt_build_dir)
    alt_vault = alt_build_dir / f"USBLockerPro_rebuild_{int(time.time())}.usbvl"
    final_tmp = vault_path.with_suffix(".tmp")
    _swap_build_and_install(alt_vault, vault_path, final_tmp, master_key,
                             lambda p: _write_vault(alt_vault, key_entries, files, master_key, p),
                             progress, phase, after_verified=after_verified)
    return wipe_failures


def _swap_build_and_install(alt_vault, vault_path, final_tmp, master_key,
                             build_fn, progress=None, phase=None, capture=None,
                             after_verified=None):
    """Shared swap used by both save and create when building at an
    alternate location:
        1. build the new vault at alt_vault
        2. verify it cryptographically there
        3. after_verified() - safe point to free up space (see below)
        4. remove the old vault, copy the verified one onto the drive
           (with visible progress - see copy_with_progress)
        5. verify the copy ON the drive, and only then delete the alt build

    Step 3 is where the unlocked plaintext folder gets wiped. That timing
    is deliberate: once step 2 confirms the new vault is complete and
    authentic, the plaintext folder is fully redundant, so erasing it
    BEFORE the copy frees the maximum possible space for step 4. Doing it
    after the copy (as an earlier version did) meant the drive had to hold
    the old vault, the new vault AND the plaintext all at once.

    The alt build is deliberately kept until step 5 confirms the on-drive
    copy is complete and authentic. If anything fails or is interrupted,
    the alt build is still there as a full, verified copy of your data, and
    the app says exactly where it is instead of silently discarding it."""
    def say(text):
        if phase:
            phase(text)

    say("Encrypting your files...")
    build_fn(progress)
    if capture is not None and "mk" in capture:
        master_key = capture["mk"]

    say("Checking the new vault is complete and correct...")
    alt_header = read_vault_header(alt_vault)
    verify_vault_with_key(alt_vault, master_key, alt_header, progress)

    # Safe point: the new vault is proven good, so anything redundant can go.
    if after_verified is not None:
        after_verified(say, progress)

    say("Removing the old vault to make room...")
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    if vault_path.exists():
        vault_path.unlink()
    # Clear any stranded .tmp from a previously interrupted swap, so the
    # copy below starts from a clean slate.
    if final_tmp.exists():
        try:
            final_tmp.unlink()
        except Exception:
            pass

    try:
        say("Copying the vault onto the USB drive (this is the slow part)...")
        copy_with_progress(alt_vault, final_tmp, progress)
        os.replace(final_tmp, vault_path)

        say("Final check of the vault on the USB drive...")
        installed_header = read_vault_header(vault_path)
        verify_vault_with_key(vault_path, master_key, installed_header, progress)
    except Exception as e:
        # The on-drive copy failed or was interrupted. Don't touch the alt
        # build - it's the only complete copy of the data right now.
        try:
            if final_tmp.exists():
                final_tmp.unlink()
        except Exception:
            pass
        raise ValueError(
            f"Could not finish putting the vault onto the USB drive: {e}\n\n"
            f"YOUR DATA IS SAFE. A complete, verified copy of the new vault is "
            f"still here:\n{alt_vault}\n\n"
            f"To finish by hand: copy that file onto the USB drive as\n"
            f"{vault_path}\n"
            f"(create the folder if needed). Do not delete the file above until "
            f"you've confirmed the copy on the USB opens correctly."
        )

    # Only now, with a verified copy confirmed on the drive, is it safe to
    # remove the alternate build.
    say("Cleaning up temporary files...")
    try:
        secure_overwrite(alt_vault)
    except Exception:
        pass


def verify_vault_with_key(vault_path, master_key, header, progress=None):
    files = header.get("files", [])
    if not files:
        raise ValueError("This vault has no files stored in it.")
    total = sum(x.get("size", 0) for x in files) or 1
    done = 0
    version = header.get("version", 3)
    with Path(vault_path).open("rb") as f:
        if version >= 4:
            chunk_size = header.get("chunk_size", CHUNK_SIZE)
            f.seek(len(FORMAT) + header.get("_reserved", HEADER_RESERVED))
            for entry in files:
                rel_path = entry["path"]
                for idx, plain_len in enumerate(_iter_chunk_plain_lens(entry.get("size", 0), chunk_size)):
                    nonce = f.read(NONCE_LEN)
                    cipher_len = int.from_bytes(f.read(8), "big")
                    cipher = f.read(cipher_len)
                    aad = f"{rel_path}|{idx}|{plain_len}".encode()
                    try:
                        AESGCM(master_key).decrypt(nonce, cipher, aad)
                    except Exception:
                        raise ValueError("Data authentication failed (vault may be corrupted).")
                    done += plain_len
                    if progress:
                        progress(done, total)
        else:
            # Legacy (v3) vaults store explicit per-chunk offsets.
            for entry in files:
                rel_path = entry["path"]
                for idx, c in enumerate(entry.get("chunks", [])):
                    f.seek(c["offset"])
                    nonce = f.read(c["nonce_len"])
                    cipher_len = int.from_bytes(f.read(8), "big")
                    cipher = f.read(cipher_len)
                    aad = f"{rel_path}|{idx}|{c['plain_len']}".encode()
                    try:
                        AESGCM(master_key).decrypt(nonce, cipher, aad)
                    except Exception:
                        raise ValueError("Data authentication failed (vault may be corrupted).")
                    done += c["plain_len"]
                    if progress:
                        progress(done, total)


def decrypt_vault_with_key(vault_path, destination, master_key, header, progress=None):
    files = header.get("files", [])
    if not files:
        raise ValueError("This vault has no files stored in it.")
    total = sum(x.get("size", 0) for x in files) or 1
    done = 0
    since_sync = 0
    destination = Path(destination)
    version = header.get("version", 3)
    try:
        with Path(vault_path).open("rb") as f:
            if version >= 4:
                chunk_size = header.get("chunk_size", CHUNK_SIZE)
                f.seek(len(FORMAT) + header.get("_reserved", HEADER_RESERVED))
                for entry in files:
                    rel_path = entry["path"]
                    out_path = safe_join(destination, rel_path)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with out_path.open("wb") as out:
                        for idx, plain_len in enumerate(_iter_chunk_plain_lens(entry.get("size", 0), chunk_size)):
                            nonce = f.read(NONCE_LEN)
                            cipher_len = int.from_bytes(f.read(8), "big")
                            cipher = f.read(cipher_len)
                            aad = f"{rel_path}|{idx}|{plain_len}".encode()
                            try:
                                plain = AESGCM(master_key).decrypt(nonce, cipher, aad)
                            except Exception:
                                raise ValueError("Data authentication failed (vault may be corrupted).")
                            out.write(plain)
                            done += len(plain)
                            since_sync += len(plain)
                            if since_sync >= SYNC_EVERY_BYTES:
                                out.flush()
                                os.fsync(out.fileno())
                                since_sync = 0
                            if progress:
                                progress(done, total)
            else:
                # Legacy (v3) vaults store explicit per-chunk offsets.
                for entry in files:
                    rel_path = entry["path"]
                    out_path = safe_join(destination, rel_path)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with out_path.open("wb") as out:
                        for idx, c in enumerate(entry.get("chunks", [])):
                            f.seek(c["offset"])
                            nonce = f.read(c["nonce_len"])
                            cipher_len = int.from_bytes(f.read(8), "big")
                            cipher = f.read(cipher_len)
                            aad = f"{rel_path}|{idx}|{c['plain_len']}".encode()
                            try:
                                plain = AESGCM(master_key).decrypt(nonce, cipher, aad)
                            except Exception:
                                raise ValueError("Data authentication failed (vault may be corrupted).")
                            out.write(plain)
                            done += len(plain)
                            if progress:
                                progress(done, total)
    except OSError as e:
        if e.errno == errno.ENOSPC:
            secure_wipe_folder(destination)
            raise ValueError(
                "Ran out of space on the USB drive while unlocking. The partially "
                "written 'Unlocked' folder was securely deleted so nothing corrupted "
                "is left behind. Free up space on the drive (or use a bigger one), "
                "then click Unlock again."
            )
        raise


def reset_vault(drive, password):
    drive = Path(drive)
    vault = drive / VAULT_DIR_NAME / VAULT_FILE
    if not vault.exists():
        raise ValueError("No vault found on this drive.")
    header = read_vault_header(vault)
    key_entries = header.get("keys", [])
    master_key, _entry = unwrap_master_key(password, key_entries)
    if master_key is None:
        raise ValueError("Incorrect password. Reset was NOT performed.")
    secure_overwrite(vault)
    vault_dir = drive / VAULT_DIR_NAME
    try:
        vault_dir.rmdir()
    except OSError:
        pass


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

class LockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("760x800")
        # Previously fixed-size, which meant long status/warning text simply
        # got clipped off the bottom edge with no way to see it. Now it can
        # be resized (and has room by default), with a floor that keeps the
        # layout from collapsing.
        self.root.minsize(700, 640)
        self.selected = tk.StringVar()
        self.status = tk.StringVar(value="Starting...")
        self.state_var = tk.StringVar(value="Detecting drive...")
        self.progress = tk.DoubleVar(value=0)
        self.progress_detail = tk.StringVar(value="")
        self.progress_phase = tk.StringVar(value="")
        self._drive_map = {}

        # Tracks the currently-unlocked session, if any.
        self.temp_dir = None
        self.master_key = None
        self.current_header = None
        self.current_vault = None

        self._drive_missing_since = None  # for poll_drive_presence's debounce
        self._operation_in_progress = False  # true for the whole duration of any run_async task

        # Remembered for the whole app session once chosen (see
        # choose_work_location): None = not asked yet this session,
        # {"mode": "usb"} = always use the USB drive itself (default,
        # matches previous behavior), {"mode": "alt", "path": Path(...)} =
        # always build/unlock at this other location instead - e.g. a
        # faster local SSD, or just to manage USB space deliberately.
        self.location_pref = None

        # Brute-force slowdown: per-vault failed attempt counts + cooldowns.
        # This is in-memory only (resets if the app restarts) - it raises
        # the cost of guessing without needing any persistent lockout state.
        self._fail_counts = {}
        self._lockout_until = {}

        self.root.configure(bg="#1b1f27")
        style = ttk.Style()
        for theme in ("vista", "clam"):
            try:
                style.theme_use(theme)
                break
            except Exception:
                continue

        ACCENT = "#3b82f6"
        style.configure("TFrame", background="#1b1f27")
        style.configure("TLabelframe", background="#1b1f27", foreground="#e5e7eb")
        style.configure("TLabelframe.Label", background="#1b1f27", foreground="#93c5fd",
                         font=("Segoe UI", 10, "bold"))
        style.configure("Header.TLabel", background="#1b1f27", foreground="#f9fafb")
        style.configure("Sub.TLabel", background="#1b1f27", foreground="#9ca3af")
        style.configure("State.TLabel", background="#1b1f27", foreground="#60a5fa")
        style.configure("Warn.TLabel", background="#1b1f27", foreground="#f0b429")
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))

        header = ttk.Frame(root)
        header.pack(fill="x", pady=(20, 4))
        ttk.Label(header, text="\U0001F512  " + APP_NAME, style="Header.TLabel",
                  font=("Segoe UI", 22, "bold")).pack()
        ttk.Label(header, text="Password-protected, portable, mutable USB vault  \u2022  AES-256-GCM + Argon2id",
                  style="Sub.TLabel").pack(pady=(2, 0))

        box = ttk.LabelFrame(root, text="USB DRIVE")
        box.pack(fill="x", padx=30, pady=12)
        self.combo = ttk.Combobox(box, textvariable=self.selected, state="readonly", width=46)
        self.combo.grid(row=0, column=0, padx=12, pady=12)
        self.combo.bind("<<ComboboxSelected>>", self.on_drive_change)
        ttk.Button(box, text="\u21bb Refresh", command=self.refresh).grid(row=0, column=1, padx=8)

        ttk.Label(root, textvariable=self.state_var, style="State.TLabel",
                  font=("Segoe UI", 10, "bold"), wraplength=640).pack(pady=(0, 8))

        vault_box = ttk.LabelFrame(root, text="VAULT")
        vault_box.pack(fill="x", padx=30, pady=6)
        self.btn_setup = ttk.Button(vault_box, text="Create NEW Vault (erases old one)", command=self.create)
        self.btn_setup.grid(row=0, column=0, padx=6, pady=8, sticky="ew")
        self.btn_unlock = ttk.Button(vault_box, text="\U0001F513 Unlock", style="Accent.TButton",
                                      command=self.unlock)
        self.btn_unlock.grid(row=0, column=1, padx=6, pady=8, sticky="ew")
        self.btn_lock_now = ttk.Button(vault_box, text="\U0001F512 Lock Now (save + wipe)",
                                        command=self.lock_now, state="disabled")
        self.btn_lock_now.grid(row=0, column=2, padx=6, pady=8, sticky="ew")
        self.btn_verify = ttk.Button(vault_box, text="Verify Vault", command=self.verify)
        self.btn_verify.grid(row=1, column=0, padx=6, pady=(0, 8), sticky="ew")
        self.btn_copy_out = ttk.Button(vault_box, text="Copy Unlocked Files To...",
                                        command=self.copy_out, state="disabled")
        self.btn_copy_out.grid(row=1, column=1, padx=6, pady=(0, 8), sticky="ew")
        self.btn_reset = ttk.Button(vault_box, text="Reset App (erase vault)", command=self.reset_app)
        self.btn_reset.grid(row=1, column=2, padx=6, pady=(0, 8), sticky="ew")
        for c in range(3):
            vault_box.columnconfigure(c, weight=1)

        recovery_box = ttk.LabelFrame(root, text="RECOVERY")
        recovery_box.pack(fill="x", padx=30, pady=6)
        self.btn_forgot = ttk.Button(recovery_box, text="Forgot Password?", command=self.forgot_password)
        self.btn_forgot.grid(row=0, column=0, padx=6, pady=8, sticky="ew")
        self.btn_topup = ttk.Button(recovery_box, text="Manage Recovery Keys...",
                                     command=self.topup_recovery)
        self.btn_topup.grid(row=0, column=1, padx=6, pady=8, sticky="ew")
        self.btn_recover_session = ttk.Button(
            recovery_box, text="\u26a0 Recover Unsaved Session...",
            command=self.recover_session, state="disabled")
        self.btn_recover_session.grid(row=1, column=0, columnspan=2, padx=6, pady=(0, 8), sticky="ew")
        for c in range(2):
            recovery_box.columnconfigure(c, weight=1)

        maint_box = ttk.LabelFrame(root, text="MAINTENANCE")
        maint_box.pack(fill="x", padx=30, pady=6)
        ttk.Button(maint_box, text="Securely Wipe a Folder...", command=self.cleanup).grid(
            row=0, column=0, padx=6, pady=8, sticky="ew")
        maint_box.columnconfigure(0, weight=1)

        sec_box = ttk.LabelFrame(root, text="SECURITY STATUS")
        sec_box.pack(fill="x", padx=30, pady=6)
        self.sec_labels = {}
        sec_rows = [
            ("encryption", "Encryption"),
            ("integrity", "Vault integrity"),
            ("state", "Vault state"),
            ("autolock", "Auto-lock on eject"),
        ]
        for i, (key, caption) in enumerate(sec_rows):
            ttk.Label(sec_box, text=caption + ":", style="Sub.TLabel",
                      font=("Segoe UI", 8)).grid(row=i // 2, column=(i % 2) * 2,
                                                  padx=(10, 4), pady=3, sticky="w")
            var = tk.StringVar(value="-")
            self.sec_labels[key] = var
            ttk.Label(sec_box, textvariable=var, style="State.TLabel",
                      font=("Segoe UI", 8, "bold")).grid(row=i // 2, column=(i % 2) * 2 + 1,
                                                          padx=(0, 10), pady=3, sticky="w")
        for c in (1, 3):
            sec_box.columnconfigure(c, weight=1)

        # Anchored to the BOTTOM so the progress/status/warning block always
        # keeps its space and can never be pushed off the window edge - this
        # is what caused text to appear cut off mid-operation.
        bottom = ttk.Frame(root)
        bottom.pack(side="bottom", fill="x", padx=30, pady=(0, 10))

        warning = ("This protects data inside vault.usbvl only - it does not encrypt "
                   "Windows itself or prevent OS-level copies/caches. Unlocking creates "
                   "an 'Unlocked' folder (on this USB drive, or another location you "
                   "choose); while it exists, those files are NOT encrypted. 'Lock Now' "
                   "saves changes back into the vault and securely erases that folder.")
        ttk.Label(bottom, text=warning, style="Warn.TLabel", wraplength=680,
                  justify="center").pack(side="bottom", pady=(6, 0))
        ttk.Label(bottom, textvariable=self.status, style="Sub.TLabel",
                  wraplength=680, justify="center").pack(side="bottom", pady=3)
        ttk.Label(bottom, textvariable=self.progress_detail, foreground="#9ca3af",
                  font=("Segoe UI", 8)).pack(side="bottom", pady=(0, 2))
        ttk.Label(bottom, textvariable=self.progress_phase, style="State.TLabel",
                  font=("Segoe UI", 9, "bold")).pack(side="bottom", pady=(4, 0))
        ttk.Progressbar(bottom, maximum=100, variable=self.progress).pack(
            side="bottom", fill="x", padx=20, pady=(10, 2))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh()
        self.update_gate_state(None)
        self.root.after(300, self.run_gate_flow)
        self.root.after(DRIVE_POLL_MS, self.poll_drive_presence)

    # ---- auto-lock on eject ----

    def poll_drive_presence(self):
        """Watches for the USB being pulled while a vault is unlocked.

        Checks whether the DRIVE ITSELF is still mounted - not whether one
        specific file exists. Those are different things: during Lock Now's
        safe swap, the app itself briefly deletes the old vault.usbvl before
        copying the new one in, which is completely normal and can take a
        while for a large vault. Checking the file's existence instead of
        the drive's mistook that normal, in-progress operation for the
        drive having been pulled. Checking the drive/root path itself
        avoids that: it stays present throughout the app's own file
        operations and only disappears when the drive is genuinely gone.

        Also skipped entirely while a background operation (run_async) is
        running, as a second layer of the same fix - the app already knows
        it's the one touching the vault file right then, so there's nothing
        to detect.

        Still requires the drive to be missing on checks spanning several
        seconds before acting, filtering a momentary USB hiccup (power-
        saving suspend, antivirus scanning, a slow controller) from an
        actual removal.

        Be clear about what this can and cannot do even when confirmed: once
        the drive is physically gone, the encrypted vault is gone with it,
        so the plaintext in the working folder CANNOT be saved back at that
        point. What this does is notice, stop the session, and - when the
        working folder is on this computer rather than the vanished drive -
        offer to securely erase that plaintext so it isn't left sitting
        around unprotected. It cannot do anything about plaintext that was
        on the removed drive itself."""
        try:
            if (self.temp_dir is not None and self.current_vault is not None
                    and not self._operation_in_progress):
                drive_root = self.current_vault.parent.parent
                still_missing = not drive_root.exists()
                if still_missing and self._drive_missing_since is None:
                    # First miss - note the time, but don't act yet.
                    self._drive_missing_since = time.time()
                elif still_missing and self._drive_missing_since is not None:
                    if time.time() - self._drive_missing_since >= DRIVE_LOST_CONFIRM_SECONDS:
                        self._drive_missing_since = None
                        self._handle_drive_lost(drive_root)
                else:
                    self._drive_missing_since = None  # it's back - false alarm
            else:
                self._drive_missing_since = None
        except Exception:
            pass
        finally:
            self.root.after(DRIVE_POLL_MS, self.poll_drive_presence)

    def _handle_drive_lost(self, drive_root):
        folder = self.temp_dir
        # Tear the session down first so nothing else tries to use it.
        self.temp_dir = None
        self.master_key = None
        self.current_header = None
        self.current_vault = None
        self.location_pref = None
        self.btn_lock_now.state(["disabled"])
        self.btn_copy_out.state(["disabled"])
        self.set_session_active(False)
        self.status.set("USB drive removed - session ended.")
        self.update_security_status(None)

        folder_on_lost_drive = False
        try:
            folder_on_lost_drive = str(folder).upper().startswith(str(drive_root).upper())
        except Exception:
            pass

        if folder_on_lost_drive:
            messagebox.showwarning(
                APP_NAME,
                f"The USB drive ({drive_root}) was removed while the vault was unlocked.\n\n"
                "The session has been ended. Any changes you made since unlocking were "
                "NOT saved back into the vault, because the vault went away with the "
                "drive.\n\nThe unlocked files were on that same drive, so they left with "
                "it too. Plug the drive back in and use 'Recover Unsaved Session' to "
                "save them properly."
            )
            return

        # Only ask about erasing it if there's actually still something
        # there. If it's already gone or empty (you may have already locked
        # or wiped it before pulling the drive), asking "should we erase
        # it?" is just noise - say so plainly instead.
        try:
            still_there = folder is not None and Path(folder).exists() and any(Path(folder).iterdir())
        except Exception:
            still_there = False

        if not still_there:
            messagebox.showinfo(
                APP_NAME,
                f"The USB drive ({drive_root}) was removed while the vault was unlocked.\n\n"
                "The session has been ended. There's nothing left to clean up - the "
                "unlocked folder was already empty or already gone."
            )
            return

        if messagebox.askyesno(
            APP_NAME,
            f"The USB drive ({drive_root}) was removed while the vault was unlocked.\n\n"
            "The session has been ended, and any changes could NOT be saved back into "
            "the vault (it went away with the drive).\n\n"
            f"Your unlocked, UNENCRYPTED files are still sitting here:\n{folder}\n\n"
            "Securely erase them now? Choose No only if you want to keep them - they "
            "stay unprotected until you deal with them."
        ):
            def task(progress, phase):
                phase("Securely erasing the unlocked copy...")
                secure_wipe_folder(folder)
            self.run_async(task, "Unlocked files were securely erased.", wants_phase=True)
        else:
            messagebox.showwarning(
                APP_NAME,
                f"Left in place, unencrypted, at:\n{folder}\n\n"
                "Plug the drive back in and use 'Recover Unsaved Session' to save them "
                "into the vault, or use 'Securely Wipe a Folder...' to erase them."
            )

    def update_security_status(self, drive, header=None, integrity=None):
        """Refreshes the SECURITY STATUS panel. integrity is an optional
        explicit result from the last verification - it is NOT inferred,
        because claiming 'verified' without actually checking would be
        worse than saying nothing."""
        self.sec_labels["encryption"].set("AES-256-GCM + Argon2id")
        self.sec_labels["autolock"].set("Active (polling)" if drive else "Idle")
        if self.temp_dir is not None:
            self.sec_labels["state"].set("\u26a0 UNLOCKED (plaintext on disk)")
        elif drive is None:
            self.sec_labels["state"].set("-")
        else:
            vault = drive / VAULT_DIR_NAME / VAULT_FILE
            self.sec_labels["state"].set("Locked" if vault.exists() else "No vault")
        if integrity is not None:
            self.sec_labels["integrity"].set(integrity)
        elif self.temp_dir is not None:
            self.sec_labels["integrity"].set("Session open")
        else:
            self.sec_labels["integrity"].set("Run 'Verify Vault' to check")

    # ---- drive selection ----

    def refresh(self):
        drives = drive_list()
        labels = []
        self._drive_map = {}
        running = detect_running_drive()
        preferred_label = None
        for d in drives:
            tag = "SYSTEM DRIVE - blocked" if is_system_drive(d) else drive_type_label(d)
            label = f"{d}  ({tag})"
            try:
                if running is not None and d.resolve() == running.resolve():
                    label += "   <- app is running from here"
                    preferred_label = label
            except Exception:
                pass
            labels.append(label)
            self._drive_map[label] = d
        self.combo["values"] = labels
        if preferred_label and self.selected.get() not in labels:
            self.selected.set(preferred_label)
        elif labels and self.selected.get() not in labels:
            self.selected.set(labels[0])
        self.status.set(f"{len(labels)} drive(s) detected.")

    def on_drive_change(self, event=None):
        self.run_gate_flow()

    def get_drive(self, silent=False):
        label = self.selected.get()
        if not label:
            if not silent:
                messagebox.showwarning(APP_NAME, "Select a drive.")
            return None
        drive = self._drive_map.get(label)
        if drive is None:
            return None
        if is_system_drive(drive):
            if not silent:
                messagebox.showerror(APP_NAME, f"{drive} is your system drive. Select your USB drive instead.")
            return None
        if not is_probably_removable(drive):
            if silent:
                return None
            if not messagebox.askyesno(
                APP_NAME,
                f"{drive} does not look like a removable USB drive "
                f"(Windows reports it as: {drive_type_label(drive)}).\n\nAre you SURE?"
            ):
                return None
        return drive

    # ---- automatic startup / drive-change gate ----

    def run_gate_flow(self):
        if self.temp_dir is not None:
            return
        drive = self.get_drive(silent=True)
        self.update_gate_state(drive)
        if drive is None:
            return
        # IMPORTANT: never auto-invoke create() here. A freshly-inserted USB
        # drive can take a moment to finish mounting, so vault.exists() can
        # transiently read False even though a real vault is sitting right
        # there - auto-launching "Create" in that window would silently
        # overwrite it with a brand-new vault (new password, new recovery
        # keys), destroying the old one. Auto-unlock is safe (worst case
        # the user cancels a password prompt); auto-create is not, so it
        # always requires an explicit button click.
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            # Retry once after a short delay in case the drive just hadn't
            # finished mounting yet.
            time.sleep(0.5)
            self.update_gate_state(drive)
        leftover = read_location_marker(drive)
        has_leftover = leftover.exists() and any(leftover.iterdir())
        if vault.exists() and not has_leftover:
            self.unlock(drive=drive)

    def update_gate_state(self, drive):
        if drive is None:
            self.state_var.set("Select your USB drive above to begin (or plug one in and click Refresh).")
            for b in (self.btn_setup, self.btn_unlock, self.btn_forgot, self.btn_verify,
                      self.btn_reset, self.btn_topup, self.btn_recover_session):
                b.state(["disabled"])
            self.update_security_status(None)
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        vault_exists = vault.exists()
        # "Create / Replace" is ALWAYS available once a drive is chosen -
        # it handles both the empty and the already-has-a-vault case itself.
        self.btn_setup.state(["!disabled"])

        # A working folder that's already sitting around, while THIS process
        # has no active session (self.temp_dir is None), means a previous
        # run ended abnormally - crash, force-kill, unplugging the drive, or
        # a power loss - before it could save + wipe. It might be on the USB
        # itself or wherever it was last unlocked to (see
        # read_location_marker) - don't silently clobber it by decrypting
        # on top of it; force a deliberate recovery step instead.
        # A stranded .tmp means a previous swap was interrupted partway
        # through copying the new vault onto the drive. Surface it plainly
        # instead of leaving a mystery file sitting there.
        stranded_tmp = vault.with_suffix(".tmp")
        if self.temp_dir is None and stranded_tmp.exists():
            if not vault_exists:
                self.state_var.set(
                    f"{drive}  -  \u26a0 An interrupted save left a partial file "
                    f"({stranded_tmp.name}) and NO finished vault on this drive. If you "
                    "still have the build copy on your other drive, copy it here as "
                    "vault.usbvl. Otherwise use 'Recover Unsaved Session' if an unlocked "
                    "folder still exists."
                )
            else:
                self.state_var.set(
                    f"{drive}  -  \u26a0 A leftover partial file ({stranded_tmp.name}) from an "
                    "interrupted save was found. Your vault is intact. Use 'Securely Wipe "
                    "a Folder...' or delete that .tmp file manually to reclaim the space."
                )

        leftover = read_location_marker(drive)
        has_leftover = self.temp_dir is None and leftover.exists() and any(leftover.iterdir()) \
            if leftover.exists() else False

        if has_leftover:
            self.btn_recover_session.state(["!disabled"])
            for b in (self.btn_unlock, self.btn_forgot, self.btn_verify, self.btn_reset, self.btn_topup):
                b.state(["disabled"])
            self.state_var.set(
                f"{drive}  -  \u26a0 An unsaved working folder was found at {leftover} (likely "
                "from a crash, force-close, or the drive being removed before Lock Now "
                "finished). Click 'Recover Unsaved Session' to save it into the vault and "
                "clean up."
            )
            return

        self.btn_recover_session.state(["disabled"])

        if vault_exists:
            n_recovery = None
            try:
                n_recovery = count_recovery_keys(read_vault_header(vault))
            except Exception:
                pass
            if n_recovery is None:
                recovery_note = ""
            elif n_recovery == 0:
                recovery_note = "  \u26a0 No recovery keys set - Forgot Password is unavailable."
            else:
                recovery_note = f"  \u2022 {n_recovery} recovery key(s) remaining."
            self.state_var.set(f"{drive}  -  Vault found. Enter your password to unlock.{recovery_note}")
            for b in (self.btn_unlock, self.btn_verify, self.btn_reset, self.btn_topup):
                b.state(["!disabled"])
            if n_recovery:
                self.btn_forgot.state(["!disabled"])
            else:
                self.btn_forgot.state(["disabled"])
        else:
            self.state_var.set(f"{drive}  -  No vault yet. Click 'Create NEW Vault' to set one up.")
            for b in (self.btn_unlock, self.btn_forgot, self.btn_verify, self.btn_reset, self.btn_topup):
                b.state(["disabled"])
        self.update_security_status(drive)

    # ---- shared helpers ----

    def choose_work_location(self, purpose):
        """Asks once per app session where large working data should live -
        directly on the USB drive (the default, matches earlier behavior)
        or a folder you pick elsewhere (e.g. a faster local SSD, or just to
        keep the USB itself less full while you work). Remembered for the
        rest of the session so you're not asked again on every single
        unlock/lock/create. Returns {"mode": "usb"} or
        {"mode": "alt", "path": Path}."""
        if self.location_pref is not None:
            return self.location_pref

        use_usb = messagebox.askyesno(
            APP_NAME,
            f"Use this USB drive itself for {purpose}? (default)\n\n"
            "Click NO to instead pick a different folder - for example your "
            "computer's SSD. That can be noticeably faster for a large vault "
            "(fewer slow writes to the flash drive), and gives you more control "
            "over how full the USB itself gets.\n\n"
            "This choice is remembered for the rest of this session."
        )
        if use_usb:
            pref = {"mode": "usb"}
        else:
            chosen = filedialog.askdirectory(
                title=f"Choose a folder to use for {purpose}")
            if chosen:
                pref = {"mode": "alt", "path": Path(chosen)}
            else:
                # Cancelled the picker - fall back to the USB default rather
                # than leaving the operation stuck with no location at all.
                pref = {"mode": "usb"}
        self.location_pref = pref
        return pref

    def password_new(self, prompt):
        p = simpledialog.askstring(APP_NAME, prompt, show="*")
        if not p:
            return None
        if len(p) < MIN_PASSWORD_LEN:
            messagebox.showwarning(APP_NAME, f"Use at least {MIN_PASSWORD_LEN} characters.")
            return None
        label, tips = password_strength(p)
        if label == "Weak":
            tip_text = "\n".join(f"- {t}" for t in tips)
            if not messagebox.askyesno(
                APP_NAME,
                f"Password strength: WEAK.\n{tip_text}\n\n"
                "You can still use it, but a weak password is the easiest way for this "
                "vault's encryption to be defeated. Use it anyway?"
            ):
                return None
        q = simpledialog.askstring(APP_NAME, "Confirm password:", show="*")
        if p != q:
            messagebox.showerror(APP_NAME, "Passwords do not match.")
            return None
        return p

    # ---- brute-force slowdown ----

    def guard_attempt(self, vault):
        """Returns True if a password attempt against this vault is allowed
        right now, or False (after showing why) if it's in cooldown."""
        key = str(vault)
        until = self._lockout_until.get(key, 0)
        remaining = until - time.time()
        if remaining > 0:
            messagebox.showwarning(
                APP_NAME,
                f"Too many wrong attempts. Please wait {int(remaining) + 1} more "
                "second(s) before trying again."
            )
            return False
        return True

    def record_failed_attempt(self, vault):
        key = str(vault)
        n = self._fail_counts.get(key, 0) + 1
        self._fail_counts[key] = n
        if n >= LOCKOUT_THRESHOLD:
            cooldown = min(LOCKOUT_BASE_SECONDS * (2 ** (n - LOCKOUT_THRESHOLD)), LOCKOUT_MAX_SECONDS)
            self._lockout_until[key] = time.time() + cooldown

    def record_success(self, vault):
        key = str(vault)
        self._fail_counts.pop(key, None)
        self._lockout_until.pop(key, None)

    def collect_recovery_keys(self):
        if not messagebox.askyesno(
            APP_NAME,
            f"Generate {RECOVERY_MAX} recovery keys now?\n\n"
            "STRONGLY RECOMMENDED. If you ever forget your password, one of these "
            "lets you set a brand-new one - like the backup codes Google/GitHub give "
            "you. Each key works ONE TIME only.\n\n"
            "Click YES to generate them (recommended).\n"
            "Click NO only if you're sure you'll never forget your password - "
            "without any recovery keys, a forgotten password cannot be recovered."
        ):
            return []
        keys = [generate_recovery_key() for _ in range(RECOVERY_MAX)]
        self.show_recovery_keys_dialog(keys)
        return keys

    def show_recovery_keys_dialog(self, keys):
        win = tk.Toplevel(self.root)
        win.title("Your Recovery Keys - Save These Now")
        win.geometry("480x360")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        ttk.Label(
            win,
            text="Write these down or save them somewhere safe (NOT on this USB drive).\n"
                 "Each works ONE TIME to reset your password if you forget it.\n"
                 "They will not be shown again after you close this window.",
            wraplength=440, foreground="#8a4b08", justify="center"
        ).pack(pady=(14, 8), padx=16)
        text = tk.Text(win, height=6, width=26, font=("Consolas", 13))
        text.insert("1.0", "\n".join(keys))
        text.configure(state="disabled")
        text.pack(pady=6)
        ttk.Button(win, text="I've saved these - Continue", command=win.destroy).pack(pady=14)
        self.root.wait_window(win)

    def run_async(self, fn, success_message, on_done=None, wants_phase=False):
        """Runs fn on a background thread with a live progress bar.

        fn is called as fn(progress) normally, or fn(progress, phase) when
        wants_phase is True. phase(text) updates the "what's happening right
        now" label under the bar, and resets the bar for the new stage - a
        multi-stage job (encrypt -> verify -> copy to USB -> final check)
        would otherwise sit at 100% during later stages and look frozen."""
        self.progress.set(0)
        self.status.set("Working... do not remove the USB.")
        self.progress_detail.set("")
        self.progress_phase.set("Starting...")
        self.root.update_idletasks()

        state = {"start": time.time(), "last_ui": 0.0, "last_done": 0, "last_t": time.time()}

        def set_phase(text):
            # New stage: restart the bar and the speed/ETA maths, so each
            # stage reports its own honest progress instead of continuing
            # from the previous stage's totals.
            state["start"] = time.time()
            state["last_ui"] = 0.0
            state["last_done"] = 0
            state["last_t"] = time.time()
            self.progress.set(0)
            self.progress_detail.set("")
            self.progress_phase.set(text)
            self.root.update_idletasks()

        def progress(done, total):
            if not total:
                return
            pct = done * 100 / total
            self.progress.set(pct)
            now = time.time()
            # Throttle detail-text updates to ~6/sec - large transfers call
            # this thousands of times, redrawing every single call would
            # itself slow things down for no benefit.
            if now - state["last_ui"] >= 0.15 or done >= total:
                dt = now - state["last_t"]
                inst_rate = (done - state["last_done"]) / dt if dt > 0 else 0
                elapsed = now - state["start"]
                avg_rate = done / elapsed if elapsed > 0 else 0
                rate = inst_rate if inst_rate > 0 else avg_rate
                remaining_bytes = max(0, total - done)
                eta = remaining_bytes / rate if rate > 0 else None
                parts = [f"{pct:.1f}%", f"{human_readable(done)} / {human_readable(total)}"]
                if rate > 0:
                    parts.append(f"{human_readable(rate)}/s")
                if eta is not None:
                    parts.append(f"{human_readable_time(eta)} left")
                self.progress_detail.set("  \u2022  ".join(parts))
                state["last_ui"] = now
                state["last_done"] = done
                state["last_t"] = now
            self.root.update_idletasks()

        def thread_safe_phase(text):
            self.root.after(0, lambda: set_phase(text))

        self._operation_in_progress = True

        def work():
            try:
                if wants_phase:
                    result = fn(progress, thread_safe_phase)
                else:
                    result = fn(progress)

                def finish():
                    self._operation_in_progress = False
                    self.progress.set(100)
                    self.progress_detail.set("")
                    self.progress_phase.set("Done.")
                    msg = success_message(result) if callable(success_message) else success_message
                    self.status.set(msg)
                    messagebox.showinfo(APP_NAME, msg)
                    if on_done:
                        on_done()
                self.root.after(0, finish)
            except Exception as e:
                def fail():
                    self._operation_in_progress = False
                    self.progress_detail.set("")
                    self.progress_phase.set("")
                    self.status.set("Operation failed.")
                    messagebox.showerror(APP_NAME, str(e))
                self.root.after(0, fail)

        threading.Thread(target=work, daemon=True).start()

    # ---- actions ----

    def create(self, drive=None):
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return

        vault_dir = drive / VAULT_DIR_NAME
        vault = vault_dir / VAULT_FILE
        if vault.exists():
            if not messagebox.askyesno(
                APP_NAME,
                "A vault already exists on this drive. Replace it? The old encrypted "
                "vault (and all its passwords/recovery keys) will be gone - this cannot be undone.\n\n"
                "If you just want to save changes to your files, use 'Lock Now' instead - "
                "this button builds a completely NEW vault from scratch."
            ):
                return
            confirm = simpledialog.askstring(
                APP_NAME,
                "This is your last chance to back out.\n\n"
                "Type REPLACE (all caps) to permanently erase the existing vault and its "
                "recovery keys, and build a new one:"
            )
            if confirm != "REPLACE":
                messagebox.showinfo(APP_NAME, "Cancelled - the existing vault was not touched.")
                return

        source = filedialog.askdirectory(title="Select the folder on this USB to protect",
                                          initialdir=str(drive))
        if not source:
            return
        source = Path(source)

        try:
            needed = sum(p.stat().st_size for p in source.rglob("*") if p.is_file())
        except Exception:
            needed = 0
        needed_with_margin = int(needed * 1.02) + 5 * 1024 * 1024
        drive_free = free_space_at(drive)
        old_vault_size = vault.stat().st_size if vault.exists() else 0

        alt_location = None
        if drive_free is not None and needed_with_margin > drive_free:
            if needed_with_margin > drive_free + old_vault_size:
                over_by = needed_with_margin - (drive_free + old_vault_size)
                messagebox.showerror(
                    APP_NAME,
                    f"'{source.name}' ({human_readable(needed)}) won't fit on {drive} even "
                    f"after removing any existing vault - about {human_readable(over_by)} "
                    f"over what the drive can hold. Choose less data or a bigger drive."
                )
                return
            proceed_msg = (
                f"Not enough free space on {drive} to build the vault while keeping the "
                f"existing one until it's confirmed safe.\n\n"
                f"Data to encrypt: about {human_readable(needed)}\n"
                f"Free on {drive} right now: {human_readable(drive_free)}\n"
                f"(would fit if the existing vault - {human_readable(old_vault_size)} - "
                f"is removed first)\n\n"
                "USB Locker Pro can build the vault on ANOTHER drive first, fully verify "
                "it there, and only then remove the old vault and move the new one onto "
                "this USB. Continue that way?"
            ) if old_vault_size else (
                f"Not enough free space on {drive} to build this vault.\n\n"
                f"Data to encrypt: about {human_readable(needed)}\n"
                f"Free on {drive}: {human_readable(drive_free)}\n\n"
                "USB Locker Pro can build the vault on ANOTHER drive first and then move "
                "the finished, verified file onto this USB. Continue that way?"
            )
            if not messagebox.askyesno(APP_NAME, proceed_msg):
                return
            alt = filedialog.askdirectory(
                title="Choose a folder with enough free space to build the vault in")
            if not alt:
                return
            alt_path = Path(alt)
            alt_free = free_space_at(alt_path)
            if alt_free is not None and needed_with_margin > alt_free:
                messagebox.showerror(
                    APP_NAME,
                    f"That location only has {human_readable(alt_free)} free - still not "
                    f"enough for the ~{human_readable(needed_with_margin)} needed."
                )
                return
            alt_location = alt_path

        main_password = self.password_new(f"Create your MAIN vault password ({MIN_PASSWORD_LEN}+ characters):")
        if not main_password:
            return

        recovery_keys = self.collect_recovery_keys()

        def task(progress, phase):
            encrypt_folder_safe(source, vault, main_password, recovery_keys,
                                 alt_build_dir=alt_location, progress=progress,
                                 phase=phase)
            phase("Confirming your recovery keys were saved...")
            # Read back what actually landed on disk rather than trusting the
            # in-memory list - turns a silent write/timing problem into a
            # loud, immediate error instead of a confusing "why does it say
            # 0 keys later" mystery.
            saved_count = count_recovery_keys(read_vault_header(vault))
            if saved_count != len(recovery_keys):
                raise ValueError(
                    f"The vault was written, but a verification read-back found "
                    f"{saved_count} recovery key(s) on disk instead of the "
                    f"{len(recovery_keys)} that were just generated. Do not rely on "
                    f"this vault - click 'Create NEW Vault' and try again, ideally on "
                    f"a different USB port/cable."
                )

        n = len(recovery_keys)
        extra = f" plus {n} recovery key(s)" if n else " (no recovery keys - if you forget it, it's gone for good)"
        alt_note = (
            f"\n\nThe vault was built and verified on {alt_location} first, then safely "
            "moved onto the USB." if alt_location is not None else ""
        )
        self.run_async(
            task,
            f"Vault created with your main password{extra}.\n\n"
            "Your original folder was NOT deleted from the USB - once you've verified "
            "the vault, delete the original copy yourself so the files aren't left "
            "sitting unprotected next to the vault." + alt_note,
            on_done=lambda: self.update_gate_state(drive),
            wants_phase=True
        )

    def set_session_active(self, active):
        """While a vault is unlocked, every other vault-level action
        (Create/Replace, Forgot Password, Manage Recovery Keys, Verify,
        Reset) is disabled. This is what stops someone from reaching for
        'Create / Replace Vault' out of habit when they actually meant
        'Lock Now' - clicking it while unlocked used to be possible and
        would silently build a brand-new vault (new password, new/no
        recovery keys) on top of the real one."""
        others = (self.btn_setup, self.btn_forgot, self.btn_topup, self.btn_verify, self.btn_reset)
        if active:
            for b in others:
                b.state(["disabled"])
            self.combo.state(["disabled"])
        else:
            self.combo.state(["!disabled"])
            self.update_gate_state(self.get_drive(silent=True))

    def unlock(self, drive=None):
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No USB Locker Pro vault was found on this drive.")
            return
        if self.temp_dir is not None:
            messagebox.showinfo(APP_NAME, "A vault is already unlocked. Click 'Lock Now' first.")
            return

        leftover = read_location_marker(drive)
        if leftover.exists() and any(leftover.iterdir()):
            messagebox.showwarning(
                APP_NAME,
                f"An unsaved working folder already exists at {leftover} from a "
                "previous session that didn't close cleanly. Unlocking again would "
                "overwrite it and lose whatever wasn't saved.\n\n"
                "Click 'Recover Unsaved Session' first to save it into the vault, "
                "then unlock normally."
            )
            self.update_gate_state(drive)
            return

        if not self.guard_attempt(vault):
            return
        password = simpledialog.askstring(
            APP_NAME,
            "Enter your vault password.\n\n(Forgot it? Use the 'Forgot Password?' button instead.)",
            show="*")
        if not password:
            return

        self.status.set("Checking password...")
        self.root.update_idletasks()
        try:
            master_key, header = check_password(vault, password)
        except ValueError as e:
            self.record_failed_attempt(vault)
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, str(e))
            return
        except Exception as e:
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, f"Could not read vault: {e}")
            return
        self.record_success(vault)

        needed = required_unlock_space(header)
        pref = self.choose_work_location("the 'Unlocked' working folder")
        on_usb = pref["mode"] == "usb"
        check_root = drive if on_usb else pref["path"]
        destination = (drive if on_usb else pref["path"]) / UNLOCKED_DIR_NAME
        used_fallback = False

        check_free = free_space_at(check_root)
        if check_free is not None and needed > check_free:
            messagebox.showwarning(
                APP_NAME,
                f"Not enough free space at {check_root} to unlock this vault.\n\n"
                f"Needed: about {human_readable(needed)}\n"
                f"Free there: {human_readable(check_free)}\n\n"
                "Choose another location with enough free space instead."
            )
            alt = filedialog.askdirectory(
                title="Choose a folder with enough free space to unlock into")
            if not alt:
                self.status.set("Ready.")
                return
            alt_path = Path(alt)
            alt_free = free_space_at(alt_path)
            if alt_free is not None and needed > alt_free:
                messagebox.showerror(
                    APP_NAME,
                    f"That location only has {human_readable(alt_free)} free - still not "
                    f"enough for the ~{human_readable(needed)} needed. Choose a different location."
                )
                self.status.set("Ready.")
                return
            destination = alt_path / UNLOCKED_DIR_NAME
            used_fallback = True
            on_usb = False
            # Remember the rescued location for the rest of this session too,
            # so this doesn't need re-solving on every unlock.
            self.location_pref = {"mode": "alt", "path": alt_path}

        def task(progress):
            decrypt_vault_with_key(vault, destination, master_key, header, progress)

        def after_success():
            self.temp_dir = destination
            self.master_key = master_key
            self.current_header = header
            self.current_vault = vault
            write_location_marker(drive, destination)
            self.btn_lock_now.state(["!disabled"])
            self.btn_copy_out.state(["!disabled"])
            self.set_session_active(True)
            # Explicitly re-show the recovery-key count right now, computed
            # from the same header that was just used to unlock - so this
            # never looks stale or blank the moment you're in.
            n_recovery = count_recovery_keys(header)
            recovery_note = (f"  \u2022 {n_recovery} recovery key(s) remaining."
                              if n_recovery else
                              "  \u26a0 No recovery keys set for this vault.")
            self.state_var.set(
                f"{drive}  -  Unlocked.{recovery_note} Edit files in the 'Unlocked' "
                "folder, then click 'Lock Now' when done."
            )
            try:
                os.startfile(str(destination))
            except Exception:
                pass

        if not on_usb:
            success_msg = (
                (f"Correct password. There wasn't enough free space on {drive}, so your "
                 f"files were unlocked to:\n{destination}"
                 if used_fallback else
                 f"Correct password. Your files were unlocked to:\n{destination}") +
                "\n\nUse it like any normal folder: open, edit, add, or delete files there.\n\n"
                "Note: this copy is NOT on the USB drive right now - it's protected only "
                "by whatever security that other location has, so click 'Lock Now' as "
                "soon as you're done (it saves back into the vault on the USB and wipes "
                "this temporary copy from wherever it currently sits)."
            )
        else:
            success_msg = (
                "Correct password. Your files are in the 'Unlocked' folder on this USB "
                "drive - use it like any normal folder: open, edit, add, or delete files "
                "there.\n\nWhen done, click 'Lock Now' to save those changes back into "
                "the encrypted vault and wipe this temporary copy."
            )

        self.run_async(task, success_msg, on_done=after_success)

    def forgot_password(self, drive=None):
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No vault found on this drive.")
            return

        try:
            header = read_vault_header(vault)
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        if count_recovery_keys(header) == 0:
            messagebox.showerror(
                APP_NAME,
                "Forgot Password is not available for this vault because no recovery "
                "keys were ever created for it (or all of them have already been used "
                "and none were regenerated afterward).\n\n"
                "Without a recovery key, a forgotten main password cannot be recovered - "
                "'Reset App' is the only remaining option, and it still requires a "
                "working password or recovery key to run."
            )
            return

        if not self.guard_attempt(vault):
            return
        key_input = simpledialog.askstring(
            APP_NAME, "Enter one of your recovery keys (format XXXXX-XXXXX-XXXXX-XXXXX):")
        if not key_input:
            return
        key_input = key_input.strip().upper()

        matched_entry = None
        master_key = None
        for entry in header.get("keys", []):
            if not entry.get("label", "").startswith("recovery"):
                continue
            mk = try_unwrap(key_input, entry)
            if mk is not None:
                master_key, matched_entry = mk, entry
                break

        if master_key is None:
            self.record_failed_attempt(vault)
            messagebox.showerror(
                APP_NAME, "That recovery key is not valid for this vault (or was already used).")
            return
        self.record_success(vault)

        new_password = self.password_new("Recovery key accepted. Create a NEW main password:")
        if not new_password:
            return

        remaining_after = count_recovery_keys(header) - 1

        def task(progress):
            rotate_main_password(vault, header, master_key, matched_entry, new_password)

        def after_reset():
            self.update_gate_state(drive)
            self.offer_recovery_topup(vault, drive, remaining_after)

        self.run_async(
            task,
            f"Your main password has been reset. The recovery key you just used is now "
            f"spent and cannot be reused. You have {remaining_after} recovery key(s) left.",
            on_done=after_reset
        )

    def offer_recovery_topup(self, vault, drive, remaining):
        """After a recovery key is spent, ask whether to burn the rest of the
        old set and issue a brand-new full set of RECOVERY_MAX keys, so the
        user isn't left slowly running out."""
        prompt = (
            f"You have {remaining} recovery key(s) left for this vault.\n\n"
            if remaining > 0 else
            "You have NO recovery keys left for this vault. If you forget your "
            "password again, it cannot be recovered.\n\n"
        )
        if not messagebox.askyesno(
            APP_NAME,
            prompt + f"Generate a fresh full set of {RECOVERY_MAX} recovery keys now? "
            "Any old, still-unused recovery keys will be replaced by the new ones."
        ):
            return

        try:
            header = read_vault_header(vault)
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        password = simpledialog.askstring(
            APP_NAME, "Enter your NEW main password to authorize generating recovery keys:",
            show="*")
        if not password:
            return
        try:
            master_key, header = check_password(vault, password)
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        new_keys = [generate_recovery_key() for _ in range(RECOVERY_MAX)]
        self.show_recovery_keys_dialog(new_keys)

        def task(progress):
            replace_recovery_keys(vault, header, master_key, new_keys)

        self.run_async(
            task,
            f"{RECOVERY_MAX} new recovery keys are active for this vault. Any older, "
            "unused recovery keys no longer work.",
            on_done=lambda: self.update_gate_state(drive)
        )

    def topup_recovery(self, drive=None):
        """Manually view/replace recovery keys at any time - not just right
        after a Forgot Password reset. Requires the current main password
        (or any still-valid recovery key) to authorize."""
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No vault found on this drive.")
            return
        try:
            header = read_vault_header(vault)
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        n_current = count_recovery_keys(header)
        if not messagebox.askyesno(
            APP_NAME,
            f"This vault currently has {n_current} recovery key(s).\n\n"
            f"Generate a fresh full set of {RECOVERY_MAX} recovery keys? Any old, "
            "still-unused recovery keys will stop working once you do."
        ):
            return

        if not self.guard_attempt(vault):
            return
        password = simpledialog.askstring(
            APP_NAME, "Enter your main password or a recovery key to authorize this:", show="*")
        if not password:
            return
        try:
            master_key, header = check_password(vault, password)
        except ValueError as e:
            self.record_failed_attempt(vault)
            messagebox.showerror(APP_NAME, str(e))
            return
        self.record_success(vault)

        new_keys = [generate_recovery_key() for _ in range(RECOVERY_MAX)]
        self.show_recovery_keys_dialog(new_keys)

        def task(progress):
            replace_recovery_keys(vault, header, master_key, new_keys)

        self.run_async(
            task,
            f"{RECOVERY_MAX} new recovery keys are active for this vault. Any older, "
            "unused recovery keys no longer work.",
            on_done=lambda: self.update_gate_state(drive)
        )

    def recover_session(self, drive=None):
        """Handles a working folder left behind by a previous run that
        didn't close cleanly (crash, force-kill, drive pulled early, power
        loss). Saves whatever is in it into the vault, the same as a normal
        Lock Now, then wipes the temporary copy. Uses read_location_marker()
        to find it, since it might not be on the USB itself."""
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        leftover = read_location_marker(drive)
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No vault found on this drive.")
            return
        if not leftover.exists() or not any(leftover.iterdir()):
            messagebox.showinfo(APP_NAME, "No unsaved session was found on this drive.")
            self.update_gate_state(drive)
            return

        if not messagebox.askyesno(
            APP_NAME,
            f"An unsaved working folder was found:\n{leftover}\n\n"
            "This will save whatever is currently in it into the encrypted vault "
            "(same as a normal Lock Now), then securely wipe the temporary copy.\n\n"
            "Continue?"
        ):
            return

        if not self.guard_attempt(vault):
            return
        password = simpledialog.askstring(
            APP_NAME, "Enter your vault password to recover this session:", show="*")
        if not password:
            return

        self.status.set("Checking password...")
        self.root.update_idletasks()
        try:
            master_key, header = check_password(vault, password)
        except ValueError as e:
            self.record_failed_attempt(vault)
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, str(e))
            return
        except Exception as e:
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, f"Could not read vault: {e}")
            return
        self.record_success(vault)
        key_entries = header.get("keys", [])

        # Same space safety net as Lock Now - a crash can happen to strike
        # right when the drive is tightest on room, so this matters here too.
        try:
            needed = sum(p.stat().st_size for p in leftover.rglob("*") if p.is_file())
        except Exception:
            needed = 0
        needed_with_margin = int(needed * 1.02) + 5 * 1024 * 1024
        old_vault_size = vault.stat().st_size if vault.exists() else 0
        drive_free = free_space_at(drive)
        alt_location = None
        if drive_free is not None and needed_with_margin > drive_free:
            if needed_with_margin > drive_free + old_vault_size:
                over_by = needed_with_margin - (drive_free + old_vault_size)
                messagebox.showerror(
                    APP_NAME,
                    f"The unsaved data ({human_readable(needed)}) won't fit back on {drive} "
                    f"even after removing the old vault - about {human_readable(over_by)} "
                    f"over what the drive can hold. Remove some files from {leftover} first."
                )
                return
            if messagebox.askyesno(
                APP_NAME,
                f"Not enough free space on {drive} to recover this session while keeping "
                f"the old vault until it's confirmed safe.\n\n"
                "USB Locker Pro can build the recovered vault on ANOTHER drive first, "
                "fully verify it, and only then replace the old vault. Continue that way?"
            ):
                alt = filedialog.askdirectory(
                    title="Choose a folder with enough free space to build the recovered vault in")
                if alt:
                    alt_path = Path(alt)
                    alt_free = free_space_at(alt_path)
                    if alt_free is None or needed_with_margin <= alt_free:
                        alt_location = alt_path
                    else:
                        messagebox.showerror(APP_NAME, "That location doesn't have enough space either.")
                        return
                else:
                    return
            else:
                return

        def task(progress, phase):
            failures = save_folder_into_vault_safe(
                leftover, vault, master_key, key_entries,
                alt_build_dir=alt_location, progress=progress,
                phase=phase, wipe_source_after_verify=True
            )
            clear_location_marker(drive)
            return failures

        def build_message(wipe_failures):
            msg = ("The unsaved session was recovered - its files are now saved in the "
                   "encrypted vault.")
            if wipe_failures:
                names = "\n".join(f"  - {p}" for p in wipe_failures[:6])
                more = f"\n  ...and {len(wipe_failures) - 6} more" if len(wipe_failures) > 6 else ""
                msg += (
                    f"\n\n\u26a0 {len(wipe_failures)} leftover file(s) could NOT be erased "
                    f"(still in use by another program):\n{names}{more}\n\nClose whatever "
                    "has them open, then use 'Securely Wipe a Folder...' on that folder."
                )
            else:
                msg += " The leftover temporary copy was securely wiped."
            return msg

        self.run_async(
            task,
            build_message,
            on_done=lambda: (setattr(self, "location_pref", None), self.update_gate_state(drive)),
            wants_phase=True
        )

    def verify(self, drive=None):
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No vault found.")
            return
        if not self.guard_attempt(vault):
            return
        password = simpledialog.askstring(APP_NAME, "Enter your main password or a recovery key:", show="*")
        if not password:
            return

        self.status.set("Checking password...")
        self.root.update_idletasks()
        try:
            master_key, header = check_password(vault, password)
        except ValueError as e:
            self.record_failed_attempt(vault)
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, str(e))
            return
        except Exception as e:
            self.status.set("Ready.")
            messagebox.showerror(APP_NAME, f"Could not read vault: {e}")
            return
        self.record_success(vault)

        def task(progress):
            verify_vault_with_key(vault, master_key, header, progress)

        def on_verified():
            self.update_security_status(
                drive, integrity=f"\u2713 Verified {time.strftime('%H:%M:%S')}")

        self.run_async(
            task,
            "Verified. Your password is correct and every encrypted block passed its "
            "authentication check - the vault has not been corrupted or tampered with.",
            on_done=on_verified
        )

    def lock_now(self):
        if self.temp_dir is None:
            return
        folder = self.temp_dir
        vault_path = self.current_vault
        master_key = self.master_key
        key_entries = self.current_header.get("keys", [])
        drive_root = vault_path.parent.parent  # .../.USBLocker/vault.usbvl -> drive

        messagebox.showinfo(
            APP_NAME,
            "Before saving: please CLOSE any File Explorer windows showing the "
            "unlocked folder, and any program with those files open (media player, "
            "Word, photo viewer, etc).\n\nWindows won't let the app erase files that "
            "another program is still holding open, and those files would be left "
            "sitting unencrypted."
        )

        choice = messagebox.askyesnocancel(
            APP_NAME,
            f"Save any changes (added, edited, or deleted files) back into the "
            f"encrypted vault?\n{folder}\n\n"
            "YES = save changes, then securely wipe this temporary copy (recommended)\n"
            "NO = discard any changes and keep the vault exactly as it was - just "
            "wipe this temporary copy (nothing to encrypt, so this is instant)\n"
            "CANCEL = do nothing, stay unlocked"
        )
        if choice is None:
            return

        if choice is False:
            def task(progress):
                secure_wipe_folder(folder)

            def after_success():
                self.temp_dir = None
                self.master_key = None
                self.current_header = None
                self.current_vault = None
                clear_location_marker(drive_root)
                self.location_pref = None  # ask fresh again next time you unlock
                self.btn_lock_now.state(["disabled"])
                self.btn_copy_out.state(["disabled"])
                self.set_session_active(False)

            self.run_async(
                task,
                "Changes were discarded - the vault is unchanged. Temporary files "
                "were securely deleted.",
                on_done=after_success
            )
            return

        # choice is True -> save. Ask (once per session) where to build the
        # updated vault, then double-check there's actually room there
        # before starting, instead of finding out partway through.
        pref = self.choose_work_location("building the updated vault before saving")
        alt_location = pref["path"] if pref["mode"] == "alt" else None

        try:
            needed = sum(p.stat().st_size for p in folder.rglob("*") if p.is_file())
        except Exception:
            needed = 0
        needed_with_margin = int(needed * 1.02) + 5 * 1024 * 1024
        old_vault_size = vault_path.stat().st_size if vault_path.exists() else 0

        if alt_location is None:
            drive_free = free_space_at(drive_root)
            if drive_free is not None and needed_with_margin > drive_free:
                # Not enough room to build the new vault ALONGSIDE the old
                # one (the normal, fastest, safest path).
                if needed_with_margin > drive_free + old_vault_size:
                    over_by = needed_with_margin - (drive_free + old_vault_size)
                    messagebox.showerror(
                        APP_NAME,
                        f"The data in 'Unlocked' ({human_readable(needed)}) won't fit on "
                        f"{drive_root} even after removing the old vault entirely - about "
                        f"{human_readable(over_by)} over what the drive can hold.\n\n"
                        "Remove some files from the 'Unlocked' folder and try Lock Now "
                        "again, or move this vault to a bigger USB drive."
                    )
                    return
                if not messagebox.askyesno(
                    APP_NAME,
                    f"Not enough free space on {drive_root} to build the updated vault "
                    f"while keeping the old one until it's confirmed safe.\n\n"
                    f"Changed data: about {human_readable(needed)}\n"
                    f"Free on {drive_root} right now: {human_readable(drive_free)}\n"
                    f"(would fit if the old vault - {human_readable(old_vault_size)} - is "
                    f"removed first)\n\n"
                    "USB Locker Pro can build the new vault on ANOTHER drive first, fully "
                    "verify it there, and only then remove the old vault and move the new "
                    "one onto this USB. Continue that way?"
                ):
                    return
                alt = filedialog.askdirectory(
                    title="Choose a folder with enough free space to build the updated vault in")
                if not alt:
                    return
                alt_path = Path(alt)
                alt_free = free_space_at(alt_path)
                if alt_free is not None and needed_with_margin > alt_free:
                    messagebox.showerror(
                        APP_NAME,
                        f"That location only has {human_readable(alt_free)} free - still "
                        f"not enough for the ~{human_readable(needed_with_margin)} needed. "
                        "Choose a different location."
                    )
                    return
                alt_location = alt_path
                # Remember this rescue location for the rest of the session.
                self.location_pref = {"mode": "alt", "path": alt_path}
        else:
            alt_free = free_space_at(alt_location)
            if alt_free is not None and needed_with_margin > alt_free:
                messagebox.showerror(
                    APP_NAME,
                    f"{alt_location} only has {human_readable(alt_free)} free - not "
                    f"enough for the ~{human_readable(needed_with_margin)} needed."
                )
                alt2 = filedialog.askdirectory(
                    title="Choose a folder with enough free space to build the updated vault in")
                if not alt2:
                    return
                alt_location = Path(alt2)
                alt_free2 = free_space_at(alt_location)
                if alt_free2 is not None and needed_with_margin > alt_free2:
                    messagebox.showerror(APP_NAME, "Still not enough space there either.")
                    return
                self.location_pref = {"mode": "alt", "path": alt_location}

        def task(progress, phase):
            # wipe_source_after_verify: the plaintext folder is erased at the
            # safe point (new vault verified, old vault untouched) rather than
            # at the very end - that frees its space BEFORE the USB copy runs.
            # A file that can't be wiped (e.g. still open in Explorer) does
            # NOT fail the save - your data is already safely in the vault by
            # then - it's returned here so the message below can be honest
            # about it instead of either lying or throwing an error.
            return save_folder_into_vault_safe(
                folder, vault_path, master_key, key_entries,
                alt_build_dir=alt_location, progress=progress,
                phase=phase, wipe_source_after_verify=True
            )

        def after_success():
            self.temp_dir = None
            self.master_key = None
            self.current_header = None
            self.current_vault = None
            clear_location_marker(drive_root)
            self.location_pref = None  # ask fresh again next time you unlock
            self.btn_lock_now.state(["disabled"])
            self.btn_copy_out.state(["disabled"])
            self.set_session_active(False)

        # Locking never changes the password/recovery-key slots (only the
        # file contents), so the count afterward is exactly what it was
        # before - stated explicitly here instead of leaving it implicit.
        n_recovery_after = sum(1 for e in key_entries if e.get("label", "").startswith("recovery"))
        recovery_note = (
            f" This vault still has {n_recovery_after} recovery key(s)."
            if n_recovery_after else
            " This vault still has NO recovery keys - use 'Manage Recovery Keys...' "
            "now if you'd like to add some, in case you ever forget your password."
        )
        alt_note = (
            f"\n\nThe updated vault was built and verified on {alt_location} first, "
            "then safely moved onto the USB."
            if alt_location is not None else ""
        )

        def build_message(wipe_failures):
            msg = "Your changes were saved to the vault." + recovery_note + alt_note
            if wipe_failures:
                names = "\n".join(f"  - {p}" for p in wipe_failures[:6])
                more = f"\n  ...and {len(wipe_failures) - 6} more" if len(wipe_failures) > 6 else ""
                msg += (
                    f"\n\n\u26a0 Your data is safely saved, but {len(wipe_failures)} file(s) "
                    f"in the unlocked folder could NOT be erased (still in use by another "
                    f"program):\n{names}{more}\n\nClose whatever has them open, then use "
                    "'Securely Wipe a Folder...' on that folder to finish cleaning up."
                )
            else:
                msg += " Temporary files were securely deleted."
            return msg

        self.run_async(
            task,
            build_message,
            on_done=after_success,
            wants_phase=True
        )

    def copy_out(self):
        if self.temp_dir is None:
            return
        dest_parent = filedialog.askdirectory(
            title="Choose where to copy the unlocked files (e.g. a folder on your laptop)")
        if not dest_parent:
            return
        dest = Path(dest_parent) / "USBLockerPro_Export"
        try:
            shutil.copytree(self.temp_dir, dest, dirs_exist_ok=True)
            messagebox.showinfo(
                APP_NAME,
                f"Copied to:\n{dest}\n\n"
                "This is a plain, UNENCRYPTED copy now sitting on that drive - it is not "
                "protected by this app. Delete it yourself when you no longer need it there."
            )
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Copy failed: {e}")

    def cleanup(self):
        folder = filedialog.askdirectory(title="Select a decrypted folder to securely delete")
        if not folder:
            messagebox.showinfo(
                APP_NAME,
                "'Securely wipe' overwrites every byte of a file with zeros BEFORE deleting "
                "it, so ordinary undelete/recovery tools have nothing readable left to find - "
                "unlike a normal delete, which just marks the space as free while the actual "
                "data often stays on disk until something else happens to overwrite it.\n\n"
                "Use this for the folder this app opened on unlock, use it (instead of "
                "'Lock Now') for any OTHER decrypted copy you made yourself - for example "
                "one you copied out with 'Copy Unlocked Files To...'.\n\n"
                "Windows/SSDs may still retain remapped copies internally; this app cannot "
                "guarantee physical erasure on flash storage."
            )
            return
        folder = Path(folder)
        if not messagebox.askyesno(
            APP_NAME,
            f"This will overwrite and permanently delete every file inside:\n{folder}\n\n"
            "This cannot be undone. Continue?"
        ):
            return

        def task(progress):
            files = [p for p in folder.rglob("*") if p.is_file()]
            total = len(files) or 1
            for i, p in enumerate(files, 1):
                secure_overwrite(p)
                progress(i, total)
            for d in sorted((p for p in folder.rglob("*") if p.is_dir()), key=lambda x: -len(str(x))):
                try:
                    d.rmdir()
                except OSError:
                    pass

        self.run_async(
            task,
            "Files were overwritten and deleted.\n\n"
            "Note: on SSD/flash storage, the controller may retain remapped copies "
            "that software cannot erase."
        )

    def reset_app(self, drive=None):
        if drive is None:
            drive = self.get_drive()
        if not drive:
            return
        vault = drive / VAULT_DIR_NAME / VAULT_FILE
        if not vault.exists():
            messagebox.showinfo(APP_NAME, "No vault to reset on this drive.")
            return

        if not messagebox.askyesno(
            APP_NAME,
            "RESET APP\n\n"
            "This permanently erases the encrypted vault on this USB drive. There is "
            "no undo, even with the correct password, once it's done. This does not "
            "touch any unencrypted original copies you may have kept elsewhere.\n\nContinue?"
        ):
            return

        if not self.guard_attempt(vault):
            return
        password = simpledialog.askstring(
            APP_NAME, "Enter your MAIN password OR any RECOVERY key to confirm reset:", show="*")
        if not password:
            return

        had_open_folder = self.temp_dir is not None
        open_folder = self.temp_dir

        def task(progress):
            try:
                reset_vault(drive, password)  # raises ValueError if the password is wrong
            except ValueError:
                self.record_failed_attempt(vault)
                raise
            self.record_success(vault)
            if had_open_folder:
                secure_wipe_folder(open_folder)

        def after_success():
            if had_open_folder:
                self.temp_dir = None
                self.master_key = None
                self.current_header = None
                self.current_vault = None
                self.btn_lock_now.state(["disabled"])
                self.btn_copy_out.state(["disabled"])
                self.set_session_active(False)
            else:
                self.update_gate_state(drive)

        self.run_async(
            task,
            "The vault on this drive has been erased. Click 'Create / Replace Vault' to set up a new one.",
            on_done=after_success
        )

    def on_close(self):
        if self.temp_dir is not None:
            if messagebox.askyesno(
                APP_NAME,
                f"A decrypted working folder is still open at {self.temp_dir}. Save "
                "changes back into the vault and wipe it before exiting? (Recommended - "
                "if you skip this, the unencrypted files stay there until you deal "
                "with them.)"
            ):
                try:
                    save_folder_into_vault(self.temp_dir, self.current_vault, self.master_key,
                                            self.current_header.get("keys", []))
                    secure_wipe_folder(self.temp_dir)
                    clear_location_marker(self.current_vault.parent.parent)
                except Exception as e:
                    messagebox.showerror(
                        APP_NAME,
                        f"Could not save on exit: {e}\n\nThe working folder was left in "
                        "place, still unencrypted, at its last location. Next time you "
                        "open this app on this drive, it will detect that and offer "
                        "'Recover Unsaved Session' to finish the job."
                    )
            else:
                messagebox.showwarning(
                    APP_NAME,
                    f"The working folder was left as-is, still unencrypted, at "
                    f"{self.temp_dir}. Next time you open this app on this drive, it "
                    "will detect that and offer 'Recover Unsaved Session' to save it "
                    "into the vault and clean up."
                )
        self.root.destroy()


# --------------------------------------------------------------------------
# Best-effort cleanup on controlled termination (Ctrl+C, SIGTERM). This is a
# SAFETY NET on top of two other layers:
#   1. The normal window-close handler (on_close), which runs every time you
#      click the X and asks to save + wipe.
#   2. Leftover-session detection at next launch (see update_gate_state /
#      recover_session), which catches anything that slipped past #1 - a
#      crash, a force-kill, the drive being pulled early, or a power loss.
# This third layer only helps for a *graceful* termination signal, where the
# interpreter gets a chance to run Python code before exiting - it cannot
# run anything after os._exit(), "End Task" in Task Manager, or a power
# loss, because by definition no code executes after those. Layer #2 is
# what actually covers those cases, by cleaning up on the NEXT launch.
_active_app_ref = {"app": None}


def _emergency_cleanup():
    app = _active_app_ref.get("app")
    if app is None or app.temp_dir is None:
        return
    try:
        if app.current_vault and app.master_key and app.current_header:
            try:
                save_folder_into_vault(
                    app.temp_dir, app.current_vault, app.master_key,
                    app.current_header.get("keys", [])
                )
                clear_location_marker(app.current_vault.parent.parent)
            except Exception:
                pass  # even if saving fails, still try to wipe below
        secure_wipe_folder(app.temp_dir)
    except Exception:
        pass


atexit.register(_emergency_cleanup)


def _signal_handler(signum, frame):
    _emergency_cleanup()
    raise SystemExit(0)


for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _signal_handler)
    except Exception:
        pass


def _resource_path(relative_path):
    """Resolve a bundled resource whether running as a script or as a
    PyInstaller --onefile exe (which unpacks data files into a temp
    folder referenced by sys._MEIPASS at runtime)."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def _set_app_icon(root):
    """Set the title bar / taskbar icon. Safe no-op if the icon file
    isn't present (e.g. running from source without assets/)."""
    try:
        icon_path = _resource_path(os.path.join("assets", "usblockerpro.ico"))
        if os.path.exists(icon_path):
            root.iconbitmap(default=icon_path)
    except Exception:
        pass  # never let a missing/broken icon stop the app from launching


if __name__ == "__main__":
    if os.name != "nt":
        messagebox.showerror(APP_NAME, "This application is designed for Windows.")
    else:
        root = tk.Tk()
        _set_app_icon(root)
        app = LockerApp(root)
        _active_app_ref["app"] = app
        root.mainloop()
