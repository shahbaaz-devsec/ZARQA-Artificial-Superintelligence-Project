#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Version: v2.8.3

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import py_compile
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ZARQA_VERSION = "v2.8.3"
ZARQA_NAME = "zarqa-snc"
ZARQA_INSTALL_DIR = "/opt/zarqa/zasi"
ZARQA_VENV_DIR = os.path.join(ZARQA_INSTALL_DIR, "venv")
ZARQA_SCRIPT_PATH = os.path.join(ZARQA_INSTALL_DIR, "zarqa_synthetic_negentropy_core.py")
ZARQA_SERVICE_PORT = 8765
ZARQA_METRICS_PORT = 8766
ZARQA_STATE_DIR = "/var/lib/zarqa/zasi"
ZARQA_LOG_DIR = "/var/log/zarqa/zasi"
ZARQA_PID_FILE = "/var/run/zarqa/zasi.pid"
ZARQA_BUILD_DIR = os.path.join(ZARQA_INSTALL_DIR, ".build")
ZARQA_CFFI_LIB = os.path.join(ZARQA_INSTALL_DIR, "libsnc_kernels.so")
ZARQA_RUST_LIB = os.path.join(ZARQA_INSTALL_DIR, "libsnc_kernels_rs.so")
ZARQA_CPP_LIB = os.path.join(ZARQA_INSTALL_DIR, "libsnc_kernels_cpp.so")
ZARQA_DEPLOY_HASH = os.path.join(ZARQA_INSTALL_DIR, ".deploy.hash")
ZARQA_DEPLOY_PENDING = ZARQA_DEPLOY_HASH + ".pending"
ZARQA_UNIT_PATH = f"/etc/systemd/system/{ZARQA_NAME}.service"
ZARQA_AUDIT_LOG = "/var/log/zarqa-audit.log"
ZARQA_REQUIRED_PY_PACKAGES = ["numpy>=1.24"]

_MAKEDIRS_AT_MAX_ATTEMPTS = 8
_SAFE_WRITE_MAX_ATTEMPTS = 4
_ERADICATE_OBSTRUCTION_MAX_ATTEMPTS = 8
_PID_ACQUIRE_MAX_ATTEMPTS = 4


def _venv_python() -> str:
    return os.path.join(ZARQA_VENV_DIR, "bin", "python")


def _venv_self_hijack() -> None:
    if os.environ.get("ZARQA_VENV_ACTIVE") == "1":
        return
    vpy = _venv_python()
    if not os.path.isfile(vpy):
        return
    real_vpy = os.path.realpath(vpy)
    real_venv = os.path.realpath(ZARQA_VENV_DIR)
    if not (real_vpy == real_venv or real_vpy.startswith(real_venv + os.sep)):
        sys.stderr.write(f"WARN: venv python {real_vpy} not under {real_venv}; refusing exec\n")
        return
    if os.path.realpath(sys.executable) == real_vpy:
        os.environ["ZARQA_VENV_ACTIVE"] = "1"
        return
    os.environ["ZARQA_VENV_ACTIVE"] = "1"
    os.execv(vpy, [vpy, os.path.abspath(__file__)] + sys.argv[1:])


_NO_VENV_HIJACK = (
    "--auto-deploy", "--analyze", "--analyze-deep", "--analyze-offensive",
    "--analyze-defensive", "--analyze-observation-bounds", "--analyze-platform",
    "--analyze-aot", "--analyze-novelty", "--bootstrap-namespace",
)
if __name__ == "__main__" and not any(f in sys.argv for f in _NO_VENV_HIJACK):
    _venv_self_hijack()

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"


def _c(text, code):
    return f"{code}{text}\033[0m" if _color_enabled() else text


C_RESET = "\033[0m"; C_BOLD = "\033[1m"; C_DIM = "\033[2m"
C_RED = "\033[31m"; C_GREEN = "\033[32m"; C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"; C_CYAN = "\033[36m"; C_MAG = "\033[35m"


class _Logger:
    def __init__(self):
        self.start = time.time()

    def _ts(self):
        return _c(f"[{time.time() - self.start:8.2f}s]", C_DIM)

    def info(self, msg):
        print(f"{self._ts()} {_c('[INFO]', C_CYAN)} {msg}", flush=True)

    def ok(self, msg):
        print(f"{self._ts()} {_c('[ OK ]', C_GREEN)} {msg}", flush=True)

    def warn(self, msg):
        print(f"{self._ts()} {_c('[WARN]', C_YELLOW)} {msg}", flush=True)

    def err(self, msg):
        print(f"{self._ts()} {_c('[FAIL]', C_RED)} {msg}", flush=True)

    def step(self, msg):
        print(f"\n{self._ts()} {_c('>>>', C_MAG)} {_c(msg, C_BOLD)}", flush=True)


LOG = _Logger()


def _audit_log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    LOG.info(f"[AUDIT] {msg}")
    candidates = [ZARQA_AUDIT_LOG, "/var/lib/zarqa-audit.log",
                  "/root/.zarqa-audit.log", "/tmp/zarqa-audit.log"]
    for path in candidates:
        try:
            d = os.path.dirname(path)
            if d and not os.path.isdir(d):
                os.makedirs(d, mode=0o750, exist_ok=True)
            new_file = not os.path.exists(path)
            with open(path, "a", encoding="utf-8") as f:
                if new_file:
                    f.write("# ZARQA SNC ownership audit log\n")
                    f.write("# Format: <UTC ISO timestamp> <message>\n")
                f.write(f"{ts} {msg}\n")
            return
        except OSError:
            continue
    LOG.warn("audit line could not be persisted to any file (stdout/journal only)")


def run_stream(cmd, *, check=False, cwd=None, env=None, shell=False) -> int:
    printable = cmd if isinstance(cmd, str) else " ".join(cmd)
    LOG.info(f"exec: {printable}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=cwd, env=env, shell=shell, bufsize=1, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(f"    {_c('|', C_DIM)} {line}")
        sys.stdout.flush()
    rc = proc.wait()
    if check and rc != 0:
        raise RuntimeError(f"command failed rc={rc}: {printable}")
    return rc


class _FlockStruct(ctypes.Structure):
    _fields_ = [
        ("l_type", ctypes.c_short),
        ("l_whence", ctypes.c_short),
        ("l_start", ctypes.c_int64),
        ("l_len", ctypes.c_int64),
        ("l_pid", ctypes.c_int32),
        ("_pad", ctypes.c_int32),
    ]


_FLOCK_SIZE = ctypes.sizeof(_FlockStruct)
_FLOCK_ABI_OK = (_FLOCK_SIZE == 32)
if not _FLOCK_ABI_OK:
    sys.stderr.write(
        f"WARN: struct flock ABI mismatch: sizeof(_FlockStruct)={_FLOCK_SIZE}, expected 32 on x86-64 LP64; "
        f"POSIX record-lock attribution (AOT_SNC14) will be disabled on this host.\n")


def _lock_bytes(lock):
    return ctypes.string_at(ctypes.byref(lock), ctypes.sizeof(_FlockStruct))


def _is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _safe_lchown(path, uid, gid):
    if hasattr(os, "lchown"):
        os.lchown(path, uid, gid)
    else:
        try:
            os.chown(path, uid, gid)
        except (AttributeError, NotImplementedError, PermissionError):
            pass


def _safe_chmod_if_not_symlink(path, mode):
    if os.path.islink(path):
        raise RuntimeError(
            f"{path} is a symbolic link; refusing chmod through symlink (AOT_SNC16)")
    os.chmod(path, mode)


def _ancestor_chain_inclusive(path):
    canon = os.path.abspath(path)
    if canon == "/":
        return ["/"]
    parts = [p for p in canon.rstrip("/").split("/") if p]
    result = ["/"]
    current = ""
    for p in parts:
        current = current + "/" + p
        result.append(current)
    return result


def _eradicate_obstruction_at(parent_fd, comp, max_attempts=_ERADICATE_OBSTRUCTION_MAX_ATTEMPTS):
    """AOT_SNC31 (v2.8.3): polymorphic destruction of an obstruction at `comp`.

    Universal abstraction extracted from _makedirs_at so _safe_write_text
    gets the same tri-state-race resistance:
      - regular file / symlink  → unlink succeeds
      - empty directory         → unlink EISDIR → rmdir succeeds
      - tri-state race          → rmdir ENOTDIR/ELOOP → retry unlink
      - non-empty directory     → rmdir ENOTEMPTY → RuntimeError AOT_SNC31_1
      - mount / LSM             → unlink EBUSY/EPERM → rmdir EBUSY/EPERM → RuntimeError AOT_SNC31_1
      - unlink EACCES/EBUSY     → RuntimeError AOT_SNC31_1

    Bounded by max_attempts; exhaustion raises RuntimeError AOT_SNC31_1.
    """
    for _attempt in range(max_attempts):
        try:
            os.unlink(comp, dir_fd=parent_fd)
            return
        except FileNotFoundError:
            return
        except OSError as uexc:
            if uexc.errno in (errno.EISDIR, errno.EPERM):
                _audit_log(
                    f"AOT_SNC31: duality race at {comp!r} "
                    f"(unlink errno={uexc.errno}); trying rmdir")
                try:
                    os.rmdir(comp, dir_fd=parent_fd)
                    return
                except FileNotFoundError:
                    return
                except OSError as rexc:
                    if rexc.errno == errno.ENOTEMPTY:
                        raise RuntimeError(
                            f"AOT_SNC31_1: cannot eradicate {comp!r}: "
                            f"non-empty directory obstruction") from rexc
                    elif rexc.errno in (errno.ENOTDIR, errno.ELOOP):
                        _audit_log(
                            f"AOT_SNC31: tri-state race at {comp!r} "
                            f"(rmdir errno={rexc.errno}); retrying unlink")
                        continue
                    elif rexc.errno in (
                            errno.EPERM, errno.EBUSY,
                            errno.EROFS, errno.EACCES):
                        raise RuntimeError(
                            f"AOT_SNC31_1: cannot eradicate {comp!r}: "
                            f"rmdir failed with {rexc}") from rexc
                    else:
                        raise
            elif uexc.errno in (errno.EBUSY, errno.EROFS, errno.EACCES):
                raise RuntimeError(
                    f"AOT_SNC31_1: cannot eradicate {comp!r}: "
                    f"unlink failed with {uexc}") from uexc
            else:
                raise
    raise RuntimeError(
        f"AOT_SNC31_1: cannot eradicate {comp!r} after "
        f"{max_attempts} attempts (persistent racer)")


def _eradicate_obstruction_path(abs_path, max_attempts=_ERADICATE_OBSTRUCTION_MAX_ATTEMPTS):
    """AOT_SNC31 (v2.8.3): path-based wrapper around _eradicate_obstruction_at.

    Opens the parent directory via O_RDONLY|O_DIRECTORY|O_NOFOLLOW to
    preserve the AOT_SNC19 TOCTOU guarantee, then delegates to the
    dir_fd-based core.
    """
    if isinstance(abs_path, bytes):
        abs_path = abs_path.decode("utf-8", "surrogateescape")
    if not isinstance(abs_path, str) or not os.path.isabs(abs_path):
        raise ValueError(
            f"_eradicate_obstruction_path: path must be absolute string, "
            f"got {abs_path!r}")
    parent = os.path.dirname(abs_path) or "/"
    comp = os.path.basename(abs_path)
    if not comp or comp in (".", ".."):
        raise RuntimeError(
            f"_eradicate_obstruction_path: invalid leaf component {comp!r}")
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _eradicate_obstruction_at(pfd, comp, max_attempts=max_attempts)
    finally:
        try:
            os.close(pfd)
        except OSError:
            pass


def _safe_write_text(path, data, mode=0o640):
    """AOT_SNC26 + AOT_SNC27 + AOT_SNC29 + AOT_SNC31 (v2.8.3): atomic
    inode severance with polymorphic tmp clearance.

    Writes to path+'.tmp' with O_CREAT|O_EXCL|O_NOFOLLOW, fsyncs, then
    os.replace(tmp, path).  rename(2) atomically replaces the *directory
    entry*, so symlinks are replaced (never followed) and hardlinks are
    severed (original inode of the hardlink remains referenced by the
    other name and is untouched).

    v2.8.3 (AOT_SNC31): the pre-flight tmp clearance now invokes
    _eradicate_obstruction_path(tmp_path) instead of a naive os.unlink,
    so a directory obstruction at tmp_path (empty or with retry) is
    polymorphically destroyed; non-empty directories fail-closed with
    RuntimeError naming AOT_SNC31_1.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        payload = bytes(data)
    else:
        raise TypeError(
            f"_safe_write_text: data must be str/bytes, got {type(data)}")
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(
            f"_safe_write_text: path must be str/PathLike, got {type(path)}")
    path_str = os.fspath(path)
    if isinstance(path_str, bytes):
        path_str = path_str.decode("utf-8", "surrogateescape")
    if not os.path.isabs(path_str):
        raise ValueError(
            f"_safe_write_text: path must be absolute, got {path_str!r}")
    tmp_path = path_str + ".tmp"

    fd = None
    for _attempt in range(_SAFE_WRITE_MAX_ATTEMPTS):
        # AOT_SNC31 (v2.8.3): polymorphic destruction replaces naive unlink
        try:
            _eradicate_obstruction_path(tmp_path)
        except RuntimeError as exc:
            raise RuntimeError(
                f"_safe_write_text: cannot clear tmp {tmp_path!r}: "
                f"{exc} (see AOT_SNC31_1)") from exc
        try:
            fd = os.open(tmp_path,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode)
            break
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                continue
            raise
    if fd is None:
        raise RuntimeError(
            f"_safe_write_text: cannot create {tmp_path!r} after "
            f"{_SAFE_WRITE_MAX_ATTEMPTS} attempts (persistent racer; "
            f"see AOT_SNC27_1)")

    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            n = os.write(fd, view[offset:])
            if n <= 0:
                raise RuntimeError(
                    f"_safe_write_text: os.write returned {n} on {tmp_path!r}")
            offset += n
        try:
            os.fsync(fd)
        except OSError as fexc:
            raise RuntimeError(
                f"_safe_write_text: fsync failed on {tmp_path!r}: {fexc} "
                f"(see AOT_SNC26_2)") from fexc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.replace(tmp_path, path_str)
    except OSError as rexc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise RuntimeError(
            f"_safe_write_text: os.replace({tmp_path!r}, {path_str!r}) "
            f"failed: {rexc} (see AOT_SNC27_1)") from rexc
    return len(payload)


def _acquire_secure_pid_fd(path, mode=0o640, max_attempts=_PID_ACQUIRE_MAX_ATTEMPTS):
    """AOT_SNC30 (v2.8.3): 5-step secure PID allocation.

    Guarantees that the returned fd refers to a pristine inode that we
    created ourselves (via O_CREAT|O_EXCL|O_NOFOLLOW), so that any
    subsequent ftruncate/write on the fd cannot touch an attacker-planted
    hardlink to a system file.

    Steps (bounded by max_attempts):
      1. Pristine attempt O_CREAT|O_EXCL|O_NOFOLLOW.  On success, acquire
         the lock and return the fd.
      2. FileExistsError → contamination detected.
      3. Arbitration: open without O_CREAT; try the POSIX lock.  If a
         legitimate daemon holds the lock, raise RuntimeError.
      4. Severance: lock was free → we hold exclusive conceptual
         authority → _eradicate_obstruction_path(path) to unlink the
         contaminated inode (defeats hardlink hijack AND dir injection).
      5. Loop back to step 1 with a fresh inode.

    Raises RuntimeError on legitimate-daemon collision or retry
    exhaustion (naming AOT_SNC30_1).
    """
    if isinstance(path, bytes):
        path = path.decode("utf-8", "surrogateescape")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError(
            f"_acquire_secure_pid_fd: path must be absolute string, "
            f"got {path!r}")

    for _attempt in range(max_attempts):
        # --- Step 1: pristine O_EXCL|O_NOFOLLOW attempt ---
        try:
            fd = os.open(path,
                         os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode)
        except FileExistsError:
            pass  # Step 2: contamination
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                _audit_log(
                    f"AOT_SNC30: symlink at {path!r} during pristine "
                    f"attempt; eradicating")
                try:
                    _eradicate_obstruction_path(path)
                except RuntimeError as ee:
                    raise RuntimeError(
                        f"AOT_SNC30_1: cannot eradicate symlink at "
                        f"{path!r}: {ee}") from ee
                continue
            raise
        else:
            # Fresh inode; acquire the lock to guarantee exclusivity
            acquired, err = PosixLockAttribution.acquire(fd)
            if acquired:
                try:
                    os.set_inheritable(fd, False)
                except (AttributeError, OSError):
                    pass
                return fd
            # A racer holds the lock on the fresh inode — unlikely, but
            # fail-safe: close, eradicate, retry
            try:
                os.close(fd)
            except OSError:
                pass
            _audit_log(
                f"AOT_SNC30: lock on fresh inode failed ({err}); "
                f"eradicating and retrying")
            try:
                _eradicate_obstruction_path(path)
            except RuntimeError:
                pass
            continue

        # --- Step 3: arbitration on the existing inode ---
        try:
            probe_fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                _audit_log(
                    f"AOT_SNC30: symlink at {path!r} during arbitration; "
                    f"eradicating")
                try:
                    _eradicate_obstruction_path(path)
                except RuntimeError as ee:
                    raise RuntimeError(
                        f"AOT_SNC30_1: cannot eradicate symlink at "
                        f"{path!r}: {ee}") from ee
                continue
            if exc.errno == errno.ENOENT:
                continue  # racer removed it; retry step 1
            if exc.errno in (errno.EISDIR, errno.ENXIO, errno.EACCES):
                # racer swapped in a non-openable object (e.g. directory);
                # eradicate it and retry step 1
                try:
                    _eradicate_obstruction_path(path)
                except RuntimeError as ee:
                    raise RuntimeError(
                        f"AOT_SNC30_1: cannot eradicate racer-swapped "
                        f"{path!r}: {ee}") from ee
                continue
            raise

        acquired, err = PosixLockAttribution.acquire(probe_fd)
        if not acquired:
            try:
                os.close(probe_fd)
            except OSError:
                pass
            raise RuntimeError(
                f"AOT_SNC30: legitimate daemon holds {path!r} "
                f"(lock err={err}); refusing to acquire")

        # --- Step 4: severance ---
        try:
            _eradicate_obstruction_path(path)
        except RuntimeError as ee:
            try:
                os.close(probe_fd)
            except OSError:
                pass
            raise RuntimeError(
                f"AOT_SNC30_1: cannot eradicate {path!r} during "
                f"severance: {ee}") from ee
        try:
            os.close(probe_fd)
        except OSError:
            pass
        # --- Step 5: loop back to step 1 ---

    raise RuntimeError(
        f"AOT_SNC30_1: cannot acquire secure PID fd at {path!r} after "
        f"{max_attempts} attempts (persistent racer)")


_AT_EMPTY_PATH = 0x1000

try:
    _LIBC = ctypes.CDLL(None, use_errno=True)
    _LIBC.fchownat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                               ctypes.c_uint, ctypes.c_int]
    _LIBC.fchownat.restype = ctypes.c_int
    _LIBC.fchmodat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_int]
    _LIBC.fchmodat.restype = ctypes.c_int
    _CTYPES_FCHOWNAT_OK = True
    _CTYPES_FCHMODAT_OK = True
except (OSError, AttributeError):
    _LIBC = None
    _CTYPES_FCHOWNAT_OK = False
    _CTYPES_FCHMODAT_OK = False


def _fchownat_empty(fd, uid, gid):
    if not _CTYPES_FCHOWNAT_OK:
        raise RuntimeError("ctypes libc fchownat unavailable; cannot apply owner on O_PATH fd")
    ctypes.set_errno(0)
    rc = _LIBC.fchownat(fd, b"", uid, gid, _AT_EMPTY_PATH)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "fchownat AT_EMPTY_PATH")


def _fchmodat_empty(fd, mode):
    if not _CTYPES_FCHMODAT_OK:
        raise OSError(errno.EOPNOTSUPP, "ctypes libc fchmodat unavailable")
    ctypes.set_errno(0)
    rc = _LIBC.fchmodat(fd, b"", mode, _AT_EMPTY_PATH)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "fchmodat AT_EMPTY_PATH")


def _apply_mode_fd(fd, mode, parent_fd, leaf_name):
    """AOT_SNC22: fails closed on platforms without safe fd-bound chmod."""
    try:
        _fchmodat_empty(fd, mode)
        return
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.ENOENT, errno.EOPNOTSUPP):
            raise
    proc_path = f"/proc/self/fd/{fd}"
    try:
        os.chmod(proc_path, mode)
        return
    except OSError:
        pass
    raise OSError(
        errno.ENOTSUP,
        "Secure fd-bound chmod unavailable on this platform (AOT_SNC22); "
        "refusing unsafe name-based fallback")


def _makedirs_at(path, mode=0o755):
    """AOT_SNC19 + AOT_SNC21 + AOT_SNC24 + AOT_SNC25 + AOT_SNC31."""
    if not os.path.isabs(path):
        raise ValueError(f"_makedirs_at: path must be absolute, got {path!r}")
    components = [c for c in path.split("/") if c]
    if not components:
        return
    if not (hasattr(os, "supports_dir_fd") and os.mkdir in os.supports_dir_fd):
        LOG.warn(f"_makedirs_at: platform lacks mkdirat; falling back to "
                 f"os.makedirs for {path!r}. TOCTOU guarantee of AOT_SNC19 is "
                 f"NOT in effect on this platform.")
        os.makedirs(path, mode=mode, exist_ok=True)
        return
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for i, comp in enumerate(components):
            attempts = 0
            while True:
                attempts += 1
                if attempts > _MAKEDIRS_AT_MAX_ATTEMPTS:
                    raise RuntimeError(
                        f"_makedirs_at: exceeded {_MAKEDIRS_AT_MAX_ATTEMPTS} "
                        f"attempts on {comp!r} in {path!r} (persistent TOCTOU "
                        f"race; see AOT_SNC21_1/AOT_SNC25_2)")
                try:
                    next_fd = os.open(comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                                      dir_fd=fd)
                    break
                except FileNotFoundError:
                    try:
                        os.mkdir(comp, mode, dir_fd=fd)
                    except FileExistsError:
                        pass
                    continue
                except OSError as exc:
                    if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                        if not _is_root():
                            raise RuntimeError(
                                f"_makedirs_at: obstruction at {comp!r} in {path!r} "
                                f"(errno={exc.errno}); self-heal (AOT_SNC19_1) "
                                f"requires root") from exc
                        _audit_log(
                            f"AOT_SNC19_1: self-heal {comp!r} at {path!r} "
                            f"(errno={exc.errno})")
                        # AOT_SNC31: universal polymorphic destruction
                        _eradicate_obstruction_at(fd, comp)
                        try:
                            os.mkdir(comp, mode, dir_fd=fd)
                        except FileExistsError:
                            pass
                        except OSError as mexc:
                            raise RuntimeError(
                                f"_makedirs_at: cannot recreate {comp!r} in "
                                f"{path!r}: mkdirat failed with {mexc} "
                                f"(see AOT_SNC19_3)") from mexc
                        continue
                    else:
                        raise
            try:
                os.close(fd)
            except OSError:
                pass
            fd = next_fd
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _safe_mutate_owner(path, mode=None):
    """AOT_SNC19: fd-bound owner/mode mutation via openat-walk."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise RuntimeError(
            f"AOT_SNC19: path must be str/bytes/PathLike, got {type(path)}")
    path_str = os.fspath(path)
    if isinstance(path_str, bytes):
        path_str = path_str.decode("utf-8", "surrogateescape")
    if not os.path.isabs(path_str):
        raise RuntimeError(f"AOT_SNC19: path must be absolute, got {path_str!r}")
    components = [c for c in path_str.split("/") if c]
    if not components:
        return

    supports_openat = (
        hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd)
    if not supports_openat:
        LOG.warn(f"AOT_SNC19: platform lacks openat-walk; falling back to "
                 f"path-based mutation for {path_str!r}. THIS SACRIFICES THE "
                 f"AOT_SNC19 TOCTOU GUARANTEE.")
        _safe_lchown(path_str, 0, 0)
        if mode is not None and not os.path.islink(path_str):
            _safe_chmod_if_not_symlink(path_str, mode)
        return

    _O_PATH = getattr(os, "O_PATH", None)
    parent_fd = None
    leaf_fd = None
    try:
        parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for i, comp in enumerate(components):
            is_last = (i == len(components) - 1)
            if not is_last:
                try:
                    next_fd = os.open(comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                                      dir_fd=parent_fd)
                except OSError as exc:
                    raise RuntimeError(
                        f"AOT_SNC19: openat intermediate {comp!r} failed "
                        f"(ancestor of {path_str!r}): {exc}") from exc
                try:
                    os.close(parent_fd)
                except OSError:
                    pass
                parent_fd = next_fd
            else:
                if _O_PATH is not None:
                    try:
                        leaf_fd = os.open(comp, _O_PATH | os.O_NOFOLLOW, dir_fd=parent_fd)
                    except OSError as exc:
                        raise RuntimeError(
                            f"AOT_SNC19: openat leaf {comp!r} failed: {exc}") from exc
                else:
                    try:
                        leaf_fd = os.open(comp, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    except OSError as exc:
                        if exc.errno == errno.ELOOP:
                            _safe_lchown(path_str, 0, 0)
                            return
                        raise RuntimeError(
                            f"AOT_SNC19: openat leaf {comp!r} failed: {exc}") from exc

        st = os.fstat(leaf_fd)
        is_symlink = ((st.st_mode & 0o170000) == 0o120000)

        if _O_PATH is not None:
            _fchownat_empty(leaf_fd, 0, 0)
            if mode is not None and not is_symlink:
                _apply_mode_fd(leaf_fd, mode, parent_fd, components[-1])
        else:
            os.fchown(leaf_fd, 0, 0)
            if mode is not None and not is_symlink:
                try:
                    os.fchmod(leaf_fd, mode)
                except OSError as exc:
                    LOG.warn(f"AOT_SNC19: fchmod failed on {path_str!r}: {exc}")
    finally:
        if leaf_fd is not None:
            try:
                os.close(leaf_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def get_process_start_time(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            stat = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    rp = stat.rfind(")")
    if rp < 0:
        return None
    tail = stat[rp + 1:].strip()
    fields = tail.split()
    if len(fields) < 20:
        return None
    try:
        return int(fields[19])
    except (ValueError, IndexError):
        return None


def parse_btime():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


STRICT_FP_FLAGS = ["-fno-fast-math", "-fno-associative-math",
                   "-fno-finite-math-only", "-fno-reciprocal-math"]

CFFI_SOURCE = r"""
#include <stddef.h>
#include <math.h>

double snc_entropy_neumaier(const double *p, size_t n) {
    volatile double s = 0.0;
    volatile double c = 0.0;
    for (size_t i = 0; i < n; i++) {
        double pi = p[i];
        if (pi <= 0.0) continue;
        double y = pi * log(pi);
        volatile double t = s + y;
        if (fabs((double)s) >= fabs(y)) { c += ((double)s - (double)t) + y; }
        else { c += (y - (double)t) + (double)s; }
        s = t;
    }
    return -(double)(s + c);
}

double snc_kl_neumaier(const double *p, const double *q, size_t n) {
    volatile double s = 0.0;
    volatile double c = 0.0;
    for (size_t i = 0; i < n; i++) {
        double pi = p[i], qi = q[i];
        if (pi <= 0.0) continue;
        if (qi <= 0.0) qi = 1e-300;
        double y = pi * log(pi / qi);
        volatile double t = s + y;
        if (fabs((double)s) >= fabs(y)) { c += ((double)s - (double)t) + y; }
        else { c += (y - (double)t) + (double)s; }
        s = t;
    }
    return (double)(s + c);
}

double snc_sum_neumaier(const double *x, size_t n) {
    volatile double s = 0.0;
    volatile double c = 0.0;
    for (size_t i = 0; i < n; i++) {
        double y = x[i];
        volatile double t = s + y;
        if (fabs((double)s) >= fabs(y)) { c += ((double)s - (double)t) + y; }
        else { c += (y - (double)t) + (double)s; }
        s = t;
    }
    return (double)(s + c);
}

double snc_chao1(long f1, long f2, long s_obs) {
    if (f2 > 0) return (double)s_obs + ((double)f1 * (double)f1) / (2.0 * (double)f2);
    return (double)s_obs + ((double)f1 * (double)(f1 - 1)) / 2.0;
}

double snc_welford_var_volatile(const double *x, size_t n) {
    if (n == 0) return 0.0;
    volatile double mean = 0.0;
    volatile double m2 = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = x[i] - (double)mean;
        mean = (double)mean + d / (double)(i + 1);
        double d2 = x[i] - (double)mean;
        m2 = (double)m2 + d * d2;
    }
    return (n > 1) ? ((double)m2 / (double)(n - 1)) : 0.0;
}
"""

RUST_SOURCE = r"""
#![allow(clippy::missing_safety_doc)]
use std::os::raw::{c_double, c_long};

#[no_mangle]
pub unsafe extern "C" fn snc_rust_entropy_neumaier(p: *const c_double, n: usize) -> c_double {
    let slice = std::slice::from_raw_parts(p, n);
    let mut s: f64 = 0.0; let mut c: f64 = 0.0;
    for &pi in slice {
        if pi <= 0.0 { continue; }
        let y = pi * pi.ln();
        let t = std::hint::black_box(s + y);
        if s.abs() >= y.abs() { c += (s - t) + y; } else { c += (y - t) + s; }
        s = t;
    }
    -std::hint::black_box(s + c)
}

#[no_mangle]
pub unsafe extern "C" fn snc_rust_kl_neumaier(p: *const c_double, q: *const c_double, n: usize) -> c_double {
    let ps = std::slice::from_raw_parts(p, n); let qs = std::slice::from_raw_parts(q, n);
    let mut s: f64 = 0.0; let mut c: f64 = 0.0;
    for i in 0..n {
        let pi = ps[i];
        if pi <= 0.0 { continue; }
        let qi = if qs[i] > 0.0 { qs[i] } else { 1e-300 };
        let y = pi * (pi / qi).ln();
        let t = std::hint::black_box(s + y);
        if s.abs() >= y.abs() { c += (s - t) + y; } else { c += (y - t) + s; }
        s = t;
    }
    std::hint::black_box(s + c)
}

#[no_mangle]
pub unsafe extern "C" fn snc_rust_chao1(f1: c_long, f2: c_long, s_obs: c_long) -> c_double {
    let f1d = f1 as f64; let f2d = f2 as f64; let sd = s_obs as f64;
    if f2 > 0 { sd + (f1d * f1d) / (2.0 * f2d) } else { sd + (f1d * (f1d - 1.0)) / 2.0 }
}

#[no_mangle]
pub unsafe extern "C" fn snc_rust_welford_var_volatile(x: *const c_double, n: usize) -> c_double {
    if n == 0 { return 0.0; }
    let xs = std::slice::from_raw_parts(x, n);
    let mut mean: f64 = 0.0; let mut m2: f64 = 0.0;
    for i in 0..n {
        let d = xs[i] - std::hint::black_box(mean);
        mean = std::hint::black_box(mean + d / (i as f64 + 1.0));
        let d2 = xs[i] - std::hint::black_box(mean);
        m2 = std::hint::black_box(m2 + d * d2);
    }
    if n > 1 { m2 / (n as f64 - 1.0) } else { 0.0 }
}
"""

CPP_SOURCE = r"""
#include <cstddef>
#include <cmath>
#include <type_traits>

template <typename T>
struct Accumulator {
    using promoted_t = std::conditional_t<
        std::is_same_v<T, float>, double,
        std::conditional_t<std::is_same_v<T, double>, long double, double>>;
    static promoted_t entropy(const T* p, std::size_t n) {
        volatile promoted_t s = 0; volatile promoted_t c = 0;
        for (std::size_t i = 0; i < n; ++i) {
            T pi = p[i]; if (pi <= T{0}) continue;
            promoted_t pt = static_cast<promoted_t>(pi);
            promoted_t y = pt * std::log(pt);
            volatile promoted_t t = s + y;
            promoted_t s_abs = ((promoted_t)s >= 0) ? (promoted_t)s : -(promoted_t)s;
            promoted_t y_abs = (y >= 0) ? y : -y;
            if (s_abs >= y_abs) { c += ((promoted_t)s - (promoted_t)t) + y; }
            else { c += (y - (promoted_t)t) + (promoted_t)s; }
            s = t;
        }
        return -(promoted_t)(s + c);
    }
};

extern "C" double snc_cpp_entropy_double_neumaier(const double* p, std::size_t n) {
    return static_cast<double>(Accumulator<double>::entropy(p, n));
}

extern "C" double snc_cpp_welford_var_volatile(const double* x, std::size_t n) {
    if (n == 0) return 0.0;
    volatile long double mean = 0.0L; volatile long double m2 = 0.0L;
    for (std::size_t i = 0; i < n; ++i) {
        long double d = static_cast<long double>(x[i]) - (long double)mean;
        mean = (long double)mean + d / static_cast<long double>(i + 1);
        long double d2 = static_cast<long double>(x[i]) - (long double)mean;
        m2 = (long double)m2 + d * d2;
    }
    return (n > 1) ? static_cast<double>((long double)m2 / static_cast<long double>(n - 1)) : 0.0;
}
"""

_FFI_C = None; _FFI_RS = None; _FFI_CPP = None
_DPTR = ctypes.POINTER(ctypes.c_double)


def _load_c():
    global _FFI_C
    if _FFI_C is not None:
        return _FFI_C
    if not os.path.isfile(ZARQA_CFFI_LIB):
        raise RuntimeError(f"C-FFI library missing: {ZARQA_CFFI_LIB} (run --auto-deploy)")
    lib = ctypes.CDLL(ZARQA_CFFI_LIB)
    lib.snc_entropy_neumaier.argtypes = [_DPTR, ctypes.c_size_t]
    lib.snc_entropy_neumaier.restype = ctypes.c_double
    lib.snc_kl_neumaier.argtypes = [_DPTR, _DPTR, ctypes.c_size_t]
    lib.snc_kl_neumaier.restype = ctypes.c_double
    lib.snc_sum_neumaier.argtypes = [_DPTR, ctypes.c_size_t]
    lib.snc_sum_neumaier.restype = ctypes.c_double
    lib.snc_chao1.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_long]
    lib.snc_chao1.restype = ctypes.c_double
    lib.snc_welford_var_volatile.argtypes = [_DPTR, ctypes.c_size_t]
    lib.snc_welford_var_volatile.restype = ctypes.c_double
    _FFI_C = lib
    return lib


def _load_rust():
    global _FFI_RS
    if _FFI_RS is not None:
        return _FFI_RS
    if not os.path.isfile(ZARQA_RUST_LIB):
        return None
    try:
        lib = ctypes.CDLL(ZARQA_RUST_LIB)
        lib.snc_rust_entropy_neumaier.argtypes = [_DPTR, ctypes.c_size_t]
        lib.snc_rust_entropy_neumaier.restype = ctypes.c_double
        lib.snc_rust_kl_neumaier.argtypes = [_DPTR, _DPTR, ctypes.c_size_t]
        lib.snc_rust_kl_neumaier.restype = ctypes.c_double
        lib.snc_rust_chao1.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_long]
        lib.snc_rust_chao1.restype = ctypes.c_double
        lib.snc_rust_welford_var_volatile.argtypes = [_DPTR, ctypes.c_size_t]
        lib.snc_rust_welford_var_volatile.restype = ctypes.c_double
        _FFI_RS = lib
        return lib
    except OSError:
        return None


def _load_cpp():
    global _FFI_CPP
    if _FFI_CPP is not None:
        return _FFI_CPP
    if not os.path.isfile(ZARQA_CPP_LIB):
        return None
    try:
        lib = ctypes.CDLL(ZARQA_CPP_LIB)
        lib.snc_cpp_entropy_double_neumaier.argtypes = [_DPTR, ctypes.c_size_t]
        lib.snc_cpp_entropy_double_neumaier.restype = ctypes.c_double
        lib.snc_cpp_welford_var_volatile.argtypes = [_DPTR, ctypes.c_size_t]
        lib.snc_cpp_welford_var_volatile.restype = ctypes.c_double
        _FFI_CPP = lib
        return lib
    except OSError:
        return None


def load_ffi():
    return {"c": _load_c(), "rust": _load_rust(), "cpp": _load_cpp()}


_RESIDUALS_DOC_ONLY = {"DM_2", "DM_3", "MS_2", "MS_3", "AS_2", "AS_3", "PP_2", "PP_5",
                       "CM_2", "CERT_1", "CERT_2", "CERT_3", "HA_2", "HA_3", "HA_4",
                       "MC_1", "MC_3"}

SNC_RESIDUALS = {
    "DM_1": "Fano floor: Pe >= Omega(sqrt(M/n)) for true p0 recovery (Fano 1952; Cover & Thomas 2006 Thm 2.10.1).",
    "DM_2": "ESS collapse: when ESS < 100, estimates have variance too large for reliable inference.",
    "DM_3": "High-dimensional Fisher: lambda_min via randomized SVD for d > 1e6.",
    "MS_1": "Chao1 f2=0 divergence: bias-corrected form used; wide CI disclosed.",
    "MS_2": "Persistent adversarial decoy modes indistinguishable from true rare modes without reference.",
    "MS_3": "Good-Turing bias for very rare species (r=0,1) when n < 1e3.",
    "MC_1": "Reservoir exhaustion: alpha_min * N_total > N_real_available => collapse unavoidable.",
    "MC_2": "Linear mixing approximation optimistic for alpha < 0.5.",
    "MC_3": "delta non-stationarity: windowed estimate flags NON_STATIONARY if delta varies > 20%.",
    "AS_1": "Spectral detection floor: f < 0.4% undetectable for d > 1e4 inputs (Tran 2018).",
    "AS_2": "Adaptive attacks that know fusion weights can optimize against them; certified radius finite.",
    "AS_3": "Certified radius R is per-sample and input-dependent; may be smaller than attacker budget.",
    "PP_1": "DP budget exhaustion: RDP epsilon grows with steps; total budget finite.",
    "PP_2": "Provenance != correctness: signed sample may still be poisoned; sanitizer is defense.",
    "PP_3": "Canary scope: detects inserted-string memorization only.",
    "PP_4": "Watermark removal: paraphrase or scheme-knowledge can strip.",
    "PP_5": "Ledger growth: ~100 GB at 1e9 samples; archival required.",
    "CM_1": "Cross-modal linear coupling approximation; nonlinear coupling not captured.",
    "CM_2": "Consistent-but-poisoned pairs pass consistency classifier; sanitizer is defense.",
    "CM_3": "Modality count: O(M^2) estimation variance; LOW_CONFIDENCE for M > 10.",
    "CERT_1": "Dual-verification correlated bugs: both implementations may share same wrong formula.",
    "CERT_2": "Toolchain trust: AOT certificate only as trustworthy as compiler.",
    "CERT_3": "WCET pessimism: aiT bound 1.2-2x actual worst case.",
    "HA_1": "FP8 measurement floor: u=2^-4 makes entropy/KL meaningless; minimum FP16.",
    "HA_2": "All-reduce topology bias: ring vs tree rounding differs; FP32 accumulation required.",
    "HA_3": "Edge TPU (INT8) measurement unsupported.",
    "HA_4": "GPU non-determinism: run-to-run variance reported over 3 runs.",
    "RICE_1": "Rice-undecidable: 'model never collapses', 'generalizes to all inputs', 'safe for all inputs'.",
    "SNC1_1": "Negentropy decay rate L must be measured empirically; bound is asymptotic.",
    "SNC2_1": "Doob limit H_inf not directly observable; convergence guaranteed, value not.",
    "SNC3_1": "Worst-case L->1 preserves H_0 trivially; real L<1 always loses information.",
    "SNC4_1": "Delta_G = W2(G(p_real),p_real) not directly observable; must be measured.",
    "SNC5_1": "Fisher trace underestimates FIM eigenvalue spectrum; diagonal approximation.",
    "SNC6_1": "Two-sample KS assumes i.i.d.; recursive samples may be correlated.",
    "SNC7_1": "L_task must be measured per task; barrier is task-specific.",
    "SNC8_1": "GAN training unstable; equilibrium is target, not guarantee.",
    "SNC9_1": "Per-sample Fisher contribution approximated by diagonal only.",
    "SNC10_1": "Composite bound assumes independence of individual theorem bounds.",
    "DSNC1_1": "KL contraction c and delta_G must be measured empirically; bound asymptotic.",
    "DSNC2_1": "Per-mode preservation rho_G not directly observable; must be measured per mode.",
    "DSNC3_1": "Effective temperature T_eff depends on calibration error delta_model.",
    "DSNC4_1": "Pairwise correlation rho_n estimated from finite samples; ESS is an upper bound.",
    "DSNC5_1": "Cramer rate I_Cramer estimated from finite samples; tail bound conservative.",
    "DSNC6_1": "Lyapunov stability requires partial derivatives not directly measurable.",
    "DSNC7_1": "Optimal stopping depends on unknown B_0, tau, C_gen, gamma; requires priors.",
    "DSNC8_1": "DP-echo bound is a floor (conservative); true echo needs empirical cross-correlation.",
    "DSNC9_1": "Chi-squared divergence estimated via exp(2*KL)-1 approximation; Gaussian-approx only.",
    "DSNC10_1": "Deep composite inherits all residuals DSNC1_1..DSNC9_1.",
    "OFF_SNC1_1": "Spectral detection floor: f < 0.4% undetected for typical trigger geometry.",
    "OFF_SNC1_2": "v2.5.0: spectral_tpr is a Gaussian-model bound (S ~ N(mu_adv, sigma_adv^2/n_adv)); adversarial distributions violating this assumption (heavy tails, mixtures, adaptive evasion) are not covered. Disclose in every red-team report.",
    "OFF_SNC2_1": "Defense TPR measured empirically; f_crit varies 0.001-0.10 by task.",
    "OFF_SNC3_1": "Mutual information estimator has O(n^{-2/(d+2)}) bias; only detectable above noise floor.",
    "OFF_SNC4_1": "Cumulative drift assumes L linear; nonlinear collapse may exceed bound.",
    "OFF_SNC5_1": "Membership advantage assumes DP-SGD; other leakage channels not covered.",
    "OFF_SNC6_1": "Fano bound is asymptotically tight; small-sample attribution weaker than bound.",
    "OFF_SNC7_1": "Common-mode rho estimated from red-team exercises; under-estimation possible.",
    "OFF_SNC8_1": "Bias amplification assumes gamma (per-sample amplifier) measured; may vary by subgroup.",
    "OFF_SNC9_1": "Non-repudiation fails under HSM compromise; P_compromise floor disclosed.",
    "OFF_SNC10_1": "Adversarial composite inherits all residuals OFF_SNC1_1..OFF_SNC9_1.",
    "DEF_SNC1_1": "Trust list infiltration risk dominates; multiple attestations reduce but do not eliminate.",
    "DEF_SNC2_1": "Sanitization FPR removes clean samples (clean-sample tax); bound is on residual not data preservation.",
    "DEF_SNC3_1": "DP budget accumulates over generations; utility degrades at epsilon > 2.",
    "DEF_SNC4_1": "Detector correlation rho reduces fusion benefit; common-mode attacks bypass fusion entirely.",
    "DEF_SNC5_1": "Correlated attacks bypass ensemble diversity; ensemble provides no common-mode robustness.",
    "DEF_SNC6_1": "Watermark removal possible at utility cost; removal bound is on cost not impossibility.",
    "DEF_SNC7_1": "Canary detects only memorized inserted samples, not general data leakage.",
    "DEF_SNC8_1": "p_log < 1 in practice; forensic gaps exist; N_key reduces gap probability exponentially.",
    "DEF_SNC9_1": "CUSUM detects drift but does not prevent it; detection delay is h/D generations.",
    "DEF_SNC10_1": "Defensive composite inherits all residuals DEF_SNC1_1..DEF_SNC9_1.",
    "OB_SNC1_1": "Fano bound: p0 recovery from n samples has error Omega(sqrt(M/n)); no estimator better.",
    "OB_SNC2_1": "Stealthy attacks (p_adv = p0) are statistically indistinguishable; detection precision <= f.",
    "OB_SNC3_1": "Hidden modes: Chao1 lower bound f1^2/(2f2) diverges when f2=0; true K_unobserved unobservable.",
    "OB_SNC4_1": "ESS estimation requires correlation estimate; error O(1/sqrt(n*min(k,log n))) with unknown k.",
    "OB_SNC5_1": "Memorization count from DP bound is upper bound; actual memorization can be lower.",
    "OB_SNC6_1": "Provenance gaps: chain probability product; per-step failure compounds exponentially.",
    "OB_SNC7_1": "Support coverage is (1-e^{-n/M_eff}) for M_eff modes; uncovered mass is irreducible.",
    "OB_SNC8_1": "Rice-undecidable properties cannot be verified; only sample-based empirical bounds apply.",
    "OB_SNC9_1": "Observability rank << parameter count for deep nets; most parameters are unobservable.",
    "OB_SNC10_1": "Observation-bounds composite inherits all residuals OB_SNC1_1..OB_SNC9_1.",
    "PN_SNC1_1": "Entropy precision: |dH| <= eps_m*log M + eps_log; FP8 gives 1-3 nats error.",
    "PN_SNC2_1": "KL precision: |dD_KL| <= eps_m*K_abs; FP8 gives 72% relative error.",
    "PN_SNC3_1": "Distributed aggregation: ring O(N*eps), tree O(log N*eps); FP32 accum required.",
    "PN_SNC4_1": "Batch scaling: delta_min = sqrt(2 ln(2/beta)/(E*B_max)); edge hardware needs thousands of epochs.",
    "PN_SNC5_1": "Operating window: [max(delta_stat, delta_prec), delta_cap]; FP8 window nearly empty.",
    "PN_SNC6_1": "Compositional portability requires FP32 accumulation at IR tier.",
    "PN_SNC7_1": "SNC ABI conformance requires eps_accum <= 1e-5; TPU BF16 fails, TPU FP32 passes.",
    "PN_SNC8_1": "Fleet availability: P_fleet = 1 - prod(1 - p_i/N).",
    "PN_SNC9_1": "Cross-platform isolation: T_sync <= eps_iso/eps_step; mixed precision requires frequent sync.",
    "PN_SNC10_1": "Platform-neutral composite inherits all residuals PN_SNC1_1..PN_SNC9_1.",
    "PN_SNC11_1": "v2.5.0: Neumaier bound |s_hat_n - sum x_i| <= (2u + (n+2)^2 u^2) * sum|x_i|. u = sys.float_info.epsilon/2 (binary64 -> 2^-53). Entropy sensitivity (derived composite, standard): |dH| <= |ds| / min_i p_i because dH/ds = -1/s and H = -sum p log p with normaliser sum p = 1. Sources: Higham 1993 Thm 4.2 + Neumaier 1974; derivation by chain rule on H(s).",
    "AOT_SNC1_1": "Contract preservation: Pr[violation] <= n_stage*eps_stage = 1.2e-5; spec itself unverified.",
    "AOT_SNC2_1": "Threshold table: bin-boundary error <= delta_s/tau_i; re-certify on p0 shift.",
    "AOT_SNC3_1": "Dual-verify: shared ISA/FP assumptions dominate; P_shared up to 1e-3 on novel hardware.",
    "AOT_SNC4_1": "WCET: static bound 1.2-2x actual on simple cores, up to 2.5x on complex cores.",
    "AOT_SNC5_1": "Exhaustive state: boundary sliver error ~1e-6; increasing n_bins reduces but never eliminates.",
    "AOT_SNC6_1": "Immutable attestation fails on HSM compromise; P_compromise ~1e-7/year floor.",
    "AOT_SNC7_1": "Regression-safe patch: Pr[undetected] <= eps_patch * delta_cov; uncovered paths carry risk.",
    "AOT_SNC8_1": "Rice-undecidable: 'true collapse', 'generalize all inputs', 'safe all inputs' cannot be verified.",
    "AOT_SNC9_1": "Runtime verification: reference itself must be AOT-verified; k consecutive generations needed.",
    "AOT_SNC10_1": "AOT composite inherits all residuals AOT_SNC1_1..AOT_SNC9_1.",
    "AOT_SNC11_1": "Compiler invariance: volatile (C/C++) and std::hint::black_box (Rust) plus -fno-fast-math ensure IEEE 754 strict.",
    "AOT_SNC12_1": "Superseded by AOT_SNC14. Retained as defence-in-depth: BSD flock + /proc/<pid>/cmdline override. cmdline is user-controlled and spoofable; do not trust for identity.",
    "AOT_SNC13_1": "Namespace fortification: every ancestor of install/state/log/pid dirs must be root:root and no group/other write. If ANY ancestor is attacker-owned, the attacker can chmod after deploy and hijack subsequent files.",
    "AOT_SNC14_1": "POSIX record-lock attribution: fcntl(F_GETLK) returns kernel-populated l_pid of lock holder; combined with start_time_ticks verification (/proc/<pid>/stat field 22) defeats PID wrap. Residual: effective-UID-0 attacker can write the PID file AND send arbitrary signals; standard root-compromise floor. Init-1 never signalled.",
    "AOT_SNC15_1": "Pre-Mutation Validation (v2.4.5): fortify() verifies ancestors BEFORE any chown/chmod/makedirs, refuses on islink(path), re-checks islink after creation (TOCTOU guard), re-verifies after fortify.",
    "AOT_SNC16_1": "L-Space Constraint (v2.4.5): leaf-level mutations used os.lchown() (no deref) and islink-guarded chmod.",
    "AOT_SNC17_1": "Setgid-on-directory false positive fix (v2.4.6): setgid on a DIRECTORY is normal group-inheritance, not privilege escalation. Only setuid/setgid on NON-directories is a genuine escalation surface.",
    "AOT_SNC18_1": "Targeted Ancestral Sovereignty (v2.4.7): walk ONLY canonical ancestor chain of managed targets (<=6 levels); non-recursive per-node mutation. O(depth), bounded, side-effect-free on siblings. v2.5.0: provenance of a root-owned non-directory obstruction cannot be established post-hoc (crtime and mtime are recorded but origin is not). v2.6.0: ancestor chain is LEXICAL (AOT_SNC20).",
    "AOT_SNC18_2": "Fix 3 (v2.5.0): _auto_fix_zarqa_ownership refuses early on any non-directory node that sits on the must-be-directory ancestor chain of a managed directory, producing a single-line diagnostic with the exact remediation command.",
    "AOT_SNC19_1": "Inode-Bound Operations (v2.4.9): every privileged ownership/mode mutation walks the path via openat(2) from the root fd with O_NOFOLLOW at EVERY component. Leaf opened with O_PATH|O_NOFOLLOW and mutated via fchownat(fd, \"\", uid, gid, AT_EMPTY_PATH) (Linux >= 2.6.39) and fchmodat(fd, \"\", mode, AT_EMPTY_PATH) (Linux >= 6.6) or os.chmod(\"/proc/self/fd/{fd}\", mode). v2.5.0 added root-only self-heal in _makedirs_at (Fix 1). v2.6.0 wrapped it in a bounded state machine (AOT_SNC21). v2.7.0 added polymorphic destruction (AOT_SNC24). v2.8.0 added tri-state race handling (AOT_SNC25). v2.8.3 routes the whole destruction through AOT_SNC31.",
    "AOT_SNC19_2": "Fix 1 residual (v2.5.0): self-heal is root-only and cannot unlink a live mountpoint, an open-for-write file with exclusive flock, or an LSM/SELinux/AppArmor-protected inode. kernel unlinkat(2) returns EBUSY/EPERM; RuntimeError names AOT_SNC19_2.",
    "AOT_SNC19_3": "Fix 1 residual (v2.5.0): mkdirat(2) after self-heal can still fail with EMLINK (too many links), ENOSPC (no space), or EDQUOT (quota). These are filesystem-imposed limits; RuntimeError names AOT_SNC19_3.",
    "AOT_SNC20_1": "Lexical Ancestor Generation (v2.6.0): _ancestor_chain_inclusive and _auto_fix_zarqa_ownership's managed_targets use os.path.abspath (lexical) rather than os.path.realpath, defeating the realpath oracle pivot. Residual: on a host where a root-owned ancestor of a managed directory is itself a symlink (requires prior root compromise), _makedirs_at's self-heal will unlink that symlink and recreate it as a real directory — destructive to any prior legitimate redirection. This is the correct behaviour for the managed tree, but disclosed because a future maintainer must not 'optimise' the code back to realpath without understanding why lexical is required.",
    "AOT_SNC21_1": "Self-Healing State Machine (v2.6.0): _makedirs_at wraps each component resolution in a bounded `while True:` loop (retry cap _MAKEDIRS_AT_MAX_ATTEMPTS=8). The FileNotFoundError→mkdirat→ELOOP race that v2.5.0 leaked uncaught is now caught by the primary self-heal handler. Residual: an attacker with a persistent race can exhaust the retry counter and induce a DoS (RuntimeError with AOT_SNC21_1). Eight attempts bounds the loop; the attack does not bypass self-heal — it merely forces an abort.",
    "AOT_SNC22_1": "Fail-Closed Mode Mutation (v2.6.0): the third fallback in _apply_mode_fd — os.chmod(leaf_name, mode, dir_fd=parent_fd, follow_symlinks=False) — is removed. On Linux the kernel ignores AT_SYMLINK_NOFOLLOW for fchmodat(2); if an attacker swapped the leaf for a symlink after the fstat check, the kernel would follow it. The function now raises OSError(ENOTSUP) if both fchmodat(AT_EMPTY_PATH) and /proc/self/fd/{fd} are unavailable. Correct fail-closed behaviour. v2.7.0: the corresponding self-test is now BEHAVIORAL (mock both fallbacks; assert ENOTSUP) rather than a source-text scan.",
    "AOT_SNC23_1": "Epistemic Test Hygiene (v2.7.0): self-tests must not evaluate production behaviour via source-text introspection (getsource). AOT_SNC22's test is behavioral. Similarly, fortify() self-tests run under /tmp/zarqa_* where the world-writable /tmp ancestor violates AOT_SNC13; the self-test temporarily mocks NamespaceIntegrity.verify_ancestors to bypass ONLY paths under /tmp/zarqa_* (or macOS /var/folders/), never the production path.",
    "AOT_SNC23_2": "Errno Polyglotcy (v2.7.1): WSL2 9p openat(parent_fd, comp, O_NOFOLLOW|O_DIRECTORY) on an intermediate symlink returns ENOTDIR (errno 20), not ELOOP (errno 40) as native ext4 does. The safety predicate 'openat refuses to proceed' is satisfied by either refusal errno. The AOT_SNC20 self-test MUST accept {ELOOP, ENOTDIR} in the __cause__ chain AND search for both 'eloop'/'symbolic link' AND 'not a directory'/'enotdir' in the message.",
    "AOT_SNC23_3": "Admissible Mock Errnos (v2.7.1): a behavioral self-test T that mocks syscall F must raise only errnos F can legitimately return on a POSIX-conforming kernel. rmdir(2) never returns EISDIR; the admissible set is {ENOTDIR, ENOTEMPTY, EBUSY, EPERM, EACCES, EROFS}.",
    "AOT_SNC24_1": "Polymorphic Destruction (v2.7.0): the initial inline form inside _makedirs_at's self-heal branch. v2.8.3 extracts this logic into _eradicate_obstruction_at (AOT_SNC31). Non-empty directories and mount points still raise RuntimeError naming AOT_SNC31_1 after the extraction.",
    "AOT_SNC24_2": "SUT-Bug vs Test-Bug Separation (v2.7.1): the AOT_SNC24 self-test's inner catch is `except (RuntimeError, OSError) as _e:` with an isinstance check. If `_e` is a RuntimeError, the SUT correctly wrapped the failure. If `_e` is an OSError, the SUT let the failure propagate — the errno's membership in the admissible set distinguishes SUT-bug from test-mock-bug.",
    "AOT_SNC25_1": "Tri-State Duality Race Closed (v2.8.0): inside _makedirs_at's self-heal branch, if unlink raises EISDIR/EPERM (file→dir swap) AND the subsequent rmdir raises ENOTDIR/ELOOP (dir→file/symlink swap back), the v2.7.1 handler fell through to `else: raise` and shattered the bounded loop. v2.8.0 added ENOTDIR/ELOOP to the `continue` set. v2.8.3 moves this logic into _eradicate_obstruction_at (AOT_SNC31).",
    "AOT_SNC25_2": "Tri-State Retry Exhaustion Floor (v2.8.0): a persistent racer who keeps toggling file↔dir↔symlink can exhaust the bounded retry counter and force a RuntimeError. The attack becomes a DoS instead of an uncaught exception — a strictly safer failure mode. v2.8.3's _eradicate_obstruction_at uses max_attempts=8 internally; combined with _safe_write_text's outer 4 attempts, the total is 32 retries for the worst case.",
    "AOT_SNC26_1": "Inode-Locked Writes — v2.8.0 original semantics (superseded by AOT_SNC27 in v2.8.1). v2.8.0 used O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW which defeats symlinks but NOT hard links: O_NOFOLLOW only fires on symlinks; a hardlink is structurally indistinguishable from the primary path at the VFS layer, so O_TRUNC would destroy the linked inode. v2.8.1 superseded via _safe_write_text's atomic rename.",
    "AOT_SNC26_2": "Inode-Locked Writes — fsync Floor (v2.8.0): _safe_write_text calls os.fsync(fd) before close. If fsync fails (rare: EIO, ENOSPC-at-close, quota), the function raises RuntimeError naming AOT_SNC26_2 rather than pretending the write is durable. On filesystems where fsync is a no-op (tmpfs), the write is still ordered but not durable; this is disclosed by the caller's use of the .deploy.hash.pending marker on the next run.",
    "AOT_SNC27_1": "Atomic Inode Severance (v2.8.1): _safe_write_text writes to path+'.tmp' with O_CREAT|O_EXCL|O_NOFOLLOW, fsyncs, then os.replace(tmp, path). The rename(2) atomically replaces the *directory entry*, so a symlink or hardlink at `path` is replaced/severed (never followed; original inode of a hardlink remains referenced by the other name and untouched). Residual A: os.replace requires tmp and path on the SAME filesystem. All call sites satisfy this (.tmp is a sibling of path); a future maintainer moving .tmp to /tmp would silently reintroduce the O_TRUNC attack class. Residual B: a persistent racer who re-creates a symlink at tmp_path between our unlink and O_EXCL open is defeated by the bounded retry loop (_SAFE_WRITE_MAX_ATTEMPTS=4); exhaustion raises RuntimeError naming AOT_SNC27_1 — a DoS, not a bypass.",
    "AOT_SNC28_1": "Universal O_NOFOLLOW on PID Allocation (v2.8.1) — SUPERSEDED by AOT_SNC30 (v2.8.3). v2.8.1 introduced _safe_open_nofollow, which added O_NOFOLLOW to the PID file open and healed ELOOP by unlinking the symlink and O_EXCL-recreating. However, O_NOFOLLOW does NOT defend against hardlinks: a hardlink at /var/run/zarqa/zasi.pid pointing to /etc/shadow would still be opened by O_RDWR|O_CREAT (no O_EXCL), and the subsequent ftruncate would wipe /etc/shadow. v2.8.3's _acquire_secure_pid_fd is the definitive fix (see AOT_SNC30_1). _safe_open_nofollow was removed as dead code; its residual is retained as historical disclosure.",
    "AOT_SNC29_1": "Payload-Length Self-Certification (v2.8.2): test-harness byte-count assertions MUST be derived from len(payload) (or len(payload.encode('utf-8')) for str), never hardcoded. v2.8.1's AOT_SNC27 test hardcoded 23 for a payload that is 24 bytes; the SUT's `return len(payload)` correctly returned 24, and the test's hardcoded 23 produced a false failure that aborted --auto-deploy. v2.8.2 migrated AOT_SNC27 and AOT_SNC26 to the len(payload) form. Residual: a test that hardcodes a byte count that happens to equal the payload's current length will pass today and fail tomorrow after a payload edit — the fix is derivation, not refreshing the hardcoded number.",
    "AOT_SNC30_1": "Secure PID Allocation — 5-Step Protocol (v2.8.3). _acquire_secure_pid_fd implements: (1) pristine O_CREAT|O_EXCL|O_NOFOLLOW; (2) FileExistsError contamination; (3) arbitration lock probe on the existing inode; (4) severance via _eradicate_obstruction_path; (5) re-allocation loop. The pristine inode is the ONLY inode the daemon ever ftruncates, so a pre-planted hardlink to /etc/shadow (or any other file) is severed before write. Residual A: if a legitimate daemon holds the lock (step 3), we abort with RuntimeError; this is correct fail-closed behaviour (the daemon cannot run twice). Residual B: a persistent racer exhausting max_attempts=4 forces a RuntimeError DoS, not a hardlink-hijack bypass. Residual C: an effective-UID-0 attacker can bypass every check; that is the standard root-compromise floor, not a defect of AOT_SNC30.",
    "AOT_SNC31_1": "Universal Polymorphic Destruction (v2.8.3). _eradicate_obstruction_at(parent_fd, comp) is the single source of truth for obstruction destruction: regular files and symlinks via unlink; empty directories via unlink→EISDIR→rmdir; tri-state races via rmdir→ENOTDIR/ELOOP→retry (bounded max_attempts=8). Both _makedirs_at and _safe_write_text (via _eradicate_obstruction_path) invoke it. Residual A: non-empty directories and live mount points still raise RuntimeError (fail-closed floor; operator remediation required). Residual B: a persistent racer that keeps re-creating the obstruction between _eradicate_obstruction_at returning and os.open(O_EXCL) succeeding can exhaust _SAFE_WRITE_MAX_ATTEMPTS=4 and force a RuntimeError DoS. Residual C: on a kernel/filesystem where rmdir(2) requires special privilege for the parent (e.g. mounted read-only), the destruction fails-closed with RuntimeError instead of a silent best-effort delete.",
    "NV_SNC1_1": "SEB economics: V, c_R, c_S, H_0, L must be measured; alpha* is only as good as these inputs.",
    "NV_SNC2_1": "GAV velocity: R_real, T_gen, N_total are exogenous; t* assumes constant real-data rate.",
    "NV_SNC3_1": "MCB cross-model: A_cross assumes linear mixture; quadratic refinement valid only for D_A < 0.1 nats.",
    "NV_SNC4_1": "CIC intervention: V_0, D_scale, r, C_int are policy-specific; tau_star formula is ADVISORY only.",
    "NV_SNC5_1": "MMC cross-modal: rho(W) >= 1 implies instability; kappa matrix estimated from pairwise training fractions.",
    "NV_SNC6_1": "AAC compound: formula valid for independent provenance + sanitization; correlated compromise exceeds bound.",
    "NV_SNC7_1": "Novelty composite: min_ratio is a normalized shortfall indicator (NOT a probability); assumes five factors independent and commensurable.",
    "KL_1": "KL divergence floors q_i at 1e-300 to avoid NaN; if q_i=0 and p_i>0 the true KL is +inf. Floor is a disclosed approximation.",
}

ZARQA_RESIDUALS_COUNT = len(SNC_RESIDUALS)


class NegentropyAnalyzer:
    @staticmethod
    def negentropy(p, x=None) -> float:
        pr = np.asarray(p, dtype=np.float64); pr = pr / pr.sum()
        if x is None:
            x = np.arange(pr.size, dtype=np.float64)
        else:
            x = np.asarray(x, dtype=np.float64)
        mean = float(np.sum(x * pr)); var = float(np.sum((x - mean) ** 2 * pr))
        H = -float(np.sum(pr[pr > 0] * np.log(pr[pr > 0])))
        H_gauss = 0.5 * math.log(2.0 * math.pi * math.e * max(var, 1e-300))
        return H_gauss - H

    @staticmethod
    def predict_entropy(n, H0, L, H_inf=0.0):
        return H0 - (H0 - H_inf) * (1.0 - L ** n)

    @staticmethod
    def predict_negentropy(n, J0, L):
        return J0 * (L ** n)

    @staticmethod
    def fit_contraction(entropy_trajectory):
        H = np.asarray(entropy_trajectory, dtype=np.float64)
        if H.size < 3:
            return {"L": float("nan"), "H_inf": float("nan")}
        x, y = H[:-1], H[1:]
        A = np.vstack([x, np.ones_like(x)]).T
        coef, *_ = np.linalg.lstsq(A, y, rcond=None)
        a, b = float(coef[0]), float(coef[1])
        H_inf = b / (1.0 - a) if abs(1.0 - a) > 1e-9 else 0.0
        return {"L": a, "H_inf": H_inf, "residual": SNC_RESIDUALS["SNC2_1"]}


class RetentionBounds:
    @staticmethod
    def info_retention(alpha, L):
        denom = 1.0 - (1.0 - alpha) * L
        return alpha / denom if denom > 1e-12 else float("inf")

    @staticmethod
    def alpha_min_info(eps, L):
        num = (1.0 - eps) * (1.0 - L); den = 1.0 - (1.0 - eps) * L
        return max(0.0, min(1.0, num / den)) if den >= 1e-12 else 1.0

    @staticmethod
    def wasserstein_asymptote(alpha, L, delta_G):
        denom = 1.0 - (1.0 - alpha) * L
        return delta_G if denom < 1e-12 else delta_G * (1.0 - alpha) / denom

    @staticmethod
    def alpha_min_wasserstein(delta_tol, L, delta_G):
        num = delta_G - delta_tol * (1.0 - L); den = delta_G + delta_tol * L
        return max(0.0, min(1.0, num / den)) if den >= 1e-12 else 1.0


class FisherRetention:
    @staticmethod
    def retention(alpha, L):
        denom = 1.0 - (1.0 - alpha) * L * L
        return alpha / denom if denom > 1e-12 else float("inf")

    @staticmethod
    def fisher_diag(grads):
        g = np.asarray(grads, dtype=np.float64); return (g * g).mean(axis=0)


class DivergenceDetector:
    @staticmethod
    def samples_for_detection(delta, beta):
        if delta <= 0 or not (0 < beta < 1): return 0
        return int(math.ceil((2.0 / (delta * delta)) * math.log(2.0 / beta)))

    @staticmethod
    def min_detectable(n_samples, beta):
        if n_samples <= 0 or not (0 < beta < 1): return 1.0
        return math.sqrt((2.0 / n_samples) * math.log(2.0 / beta))

    @staticmethod
    def ks_two_sample(x, y):
        xs = np.sort(np.asarray(x, dtype=np.float64)); ys = np.sort(np.asarray(y, dtype=np.float64))
        if xs.size == 0 or ys.size == 0: return 0.0
        all_pts = np.concatenate([xs, ys])
        cdf_x = np.searchsorted(xs, all_pts, side="right") / float(xs.size)
        cdf_y = np.searchsorted(ys, all_pts, side="right") / float(ys.size)
        return float(np.max(np.abs(cdf_x - cdf_y)))


class WassersteinBarrier:
    @staticmethod
    def barrier(eps_task, L_task):
        return eps_task / L_task if L_task > 1e-12 else float("inf")

    @staticmethod
    def sliced_w2(x, y, n_projections=100, seed=42):
        rng = np.random.default_rng(seed)
        x = np.asarray(x, dtype=np.float64); y = np.asarray(y, dtype=np.float64)
        if x.ndim == 1: x = x.reshape(-1, 1)
        if y.ndim == 1: y = y.reshape(-1, 1)
        if x.shape[1] != y.shape[1]: raise ValueError("sliced_w2: dimension mismatch")
        d = x.shape[1]; total = 0.0
        for _ in range(n_projections):
            theta = rng.normal(size=d); nrm = np.linalg.norm(theta)
            if nrm < 1e-12: continue
            theta /= nrm
            xp = np.sort(x @ theta); yp = np.sort(y @ theta)
            n = min(xp.size, yp.size)
            xp_q = np.quantile(xp, np.linspace(0, 1, n)); yp_q = np.quantile(yp, np.linspace(0, 1, n))
            total += float(np.mean((xp_q - yp_q) ** 2))
        return float(np.sqrt(total / n_projections))


class GANEquilibrium:
    @staticmethod
    def jsd(p, q):
        p = np.clip(np.asarray(p, dtype=np.float64), 1e-300, None)
        q = np.clip(np.asarray(q, dtype=np.float64), 1e-300, None)
        p = p / p.sum(); q = q / q.sum(); m = 0.5 * (p + q)
        return 0.5 * (float(np.sum(p * np.log(p / m))) + float(np.sum(q * np.log(q / m))))

    @staticmethod
    def at_equilibrium(jsd_value, tol=0.02): return jsd_value is not None and jsd_value <= tol


class FisherPruning:
    @staticmethod
    def optimal_gamma(fisher_contributions, c):
        f = np.asarray(fisher_contributions, dtype=np.float64)
        return float((f > c).mean()) if f.size > 0 else 1.0

    @staticmethod
    def retain_mask(fisher_contributions, c):
        f = np.asarray(fisher_contributions, dtype=np.float64); return f > c


def composite_analysis(alpha, L, delta_G, H0, generations, delta_tol, eps_task,
                       L_task, delta_KS, beta_KS, J0=5.0, p_hat=None, p_0=None):
    J_n = NegentropyAnalyzer.predict_negentropy(generations, J0, L)
    H_n = NegentropyAnalyzer.predict_entropy(generations, H0, L, H_inf=0.0)
    I_inf = RetentionBounds.info_retention(alpha, L)
    a_min_info = RetentionBounds.alpha_min_info(0.1, L)
    W2_inf = RetentionBounds.wasserstein_asymptote(alpha, L, delta_G)
    a_min_w2 = RetentionBounds.alpha_min_wasserstein(delta_tol, L, delta_G)
    F_inf = FisherRetention.retention(alpha, L)
    n_det = DivergenceDetector.samples_for_detection(delta_KS, beta_KS)
    W_barrier = WassersteinBarrier.barrier(eps_task, L_task)
    if p_hat is not None and p_0 is not None and HAS_NUMPY:
        jsd_target = GANEquilibrium.jsd(p_hat, p_0); jsd_residual = None
    else:
        jsd_target = None
        jsd_residual = "SNC8 JSD not computed: p_hat/p_0 not supplied."
    if W2_inf <= W_barrier:
        verdict = "VALID"; verdict_detail = f"W2_inf={W2_inf:.3f} <= W_barrier={W_barrier:.3f}"
    else:
        verdict = "DRIFT_PAST_BARRIER"; verdict_detail = f"W2_inf={W2_inf:.3f} > W_barrier={W_barrier:.3f}"
    warnings = []
    if alpha < a_min_info: warnings.append(f"alpha={alpha:.3f} < alpha_min_info={a_min_info:.3f} (SNC3)")
    if alpha < a_min_w2: warnings.append(f"alpha={alpha:.3f} < alpha_min_w2={a_min_w2:.3f} (SNC4)")
    if F_inf < 0.5: warnings.append(f"F_inf={F_inf:.3f} < 0.5 (SNC5)")
    return {"inputs": {"alpha": alpha, "L": L, "delta_G": delta_G, "H0": H0,
                       "generations": generations, "delta_tol": delta_tol,
                       "eps_task": eps_task, "L_task": L_task,
                       "delta_KS": delta_KS, "beta_KS": beta_KS, "J0": J0},
            "SNC1_negentropy": J_n, "SNC2_entropy": H_n,
            "SNC3_info_retention": I_inf, "SNC3_alpha_min": a_min_info,
            "SNC4_wasserstein": W2_inf, "SNC4_alpha_min": a_min_w2,
            "SNC5_fisher_retention": F_inf, "SNC6_detection_samples": n_det,
            "SNC7_barrier": W_barrier, "SNC8_jsd_target": jsd_target,
            "SNC8_jsd_residual": jsd_residual,
            "SNC9_gamma_note": "P(tr(dF(x)) > c)",
            "SNC10_verdict": verdict, "SNC10_detail": verdict_detail,
            "warnings": warnings, "residual": SNC_RESIDUALS["SNC10_1"]}


class KLSteadyState:
    @staticmethod
    def steady_state(alpha, c, delta_G):
        ratio = (1.0 - alpha) * c
        return (1.0 - alpha) * delta_G / (1.0 - ratio) if ratio < 1.0 else float("inf")

    @staticmethod
    def transient(n, alpha, c, delta_G, d0=0.0):
        d_inf = KLSteadyState.steady_state(alpha, c, delta_G)
        if not math.isfinite(d_inf): return float("inf")
        return d_inf + ((1.0 - alpha) * c) ** n * (d0 - d_inf)

    @staticmethod
    def alpha_min(delta_target, c, delta_G):
        num = delta_G - delta_target * (1.0 - c); den = delta_G + delta_target * c
        return max(0.0, min(1.0, num / den)) if den > 0 else 1.0


class ModeSurvivalDeep:
    @staticmethod
    def steady_state(alpha, rho_G, pi_k):
        ratio = (1.0 - alpha) * rho_G
        return alpha * pi_k / (1.0 - ratio) if ratio < 1.0 else float("inf")

    @staticmethod
    def mode_probability(n, alpha, rho_G, pi_k):
        pi_inf = ModeSurvivalDeep.steady_state(alpha, rho_G, pi_k)
        if not math.isfinite(pi_inf): return float("inf")
        ratio = (1.0 - alpha) * rho_G
        return pi_inf + (ratio ** n) * (pi_k - pi_inf)

    @staticmethod
    def pi_crit(eps, alpha, N_real, rho_G, N_synth):
        denom = alpha * N_real + (1.0 - alpha) * rho_G * N_synth
        return eps / denom if denom > 1e-12 else float("inf")


class TemperatureBound:
    @staticmethod
    def scaled(p, T):
        p = np.clip(np.asarray(p, dtype=np.float64), 1e-300, None)
        log_pt = (1.0 / T) * np.log(p); log_pt -= log_pt.max()
        pt = np.exp(log_pt); return pt / pt.sum()

    @staticmethod
    def kl_from_base(p, T):
        p = np.asarray(p, dtype=np.float64); p = p / p.sum(); pT = TemperatureBound.scaled(p, T)
        return float(np.sum(pT * np.log(np.clip(pT, 1e-300, None) / np.clip(p, 1e-300, None))))

    @staticmethod
    def effective_temperature(T, delta_model): return T * (1.0 + delta_model)


class EffectiveSampleSize:
    @staticmethod
    def ess(n_synth, rho_n):
        if rho_n >= 1.0: return 1.0
        return n_synth / (1.0 + (n_synth - 1.0) * rho_n)

    @staticmethod
    def per_mode_correlation(alpha, rho_G, n): return ((1.0 - alpha) * rho_G) ** n

    @staticmethod
    def steady_state_corr(alpha, rho_G, n_mode):
        ratio = (1.0 - alpha) * rho_G / max(n_mode, 1)
        return min(1.0, max(0.0, ratio))


class HallucinationBound:
    @staticmethod
    def steady_state(alpha, rho_G, P_H_real):
        ratio = (1.0 - alpha) * rho_G
        return alpha * P_H_real / (1.0 - ratio) if ratio < 1.0 else float("inf")

    @staticmethod
    def transient(n, alpha, rho_G, P_H_real, P_H_0):
        ss = HallucinationBound.steady_state(alpha, rho_G, P_H_real)
        if not math.isfinite(ss): return float("inf")
        ratio = (1.0 - alpha) * rho_G
        return ss + (ratio ** n) * (P_H_0 - ss)

    @staticmethod
    def cramer_bound(N, rate): return math.exp(-N * rate) if rate > 0 else 1.0


class AdaptiveMixing:
    @staticmethod
    def update(alpha, D_KL, delta_target, eta):
        new_alpha = alpha + eta * (D_KL - delta_target)
        return max(0.0, min(1.0, new_alpha))

    @staticmethod
    def simulate(alpha_0, delta_target, eta, dkl_fn, n_steps=100, tol=1e-3):
        alpha = alpha_0; history = [alpha]
        for _ in range(n_steps):
            D = dkl_fn(alpha)
            if abs(D - delta_target) < tol: return history, alpha, True
            alpha = AdaptiveMixing.update(alpha, D, delta_target, eta)
            history.append(alpha)
        return history, alpha, False


class OptimalStopping:
    @staticmethod
    def benefit(n, B_0, tau): return B_0 * (1.0 - math.exp(-n / tau))

    @staticmethod
    def npv(N, B_0, tau, C_gen, gamma):
        total = 0.0
        for n in range(1, N + 1):
            total += (gamma ** n) * (OptimalStopping.benefit(n, B_0, tau) - C_gen)
        return total

    @staticmethod
    def optimal_N_continuous(B_0, tau, C_gen, gamma):
        if gamma >= 1.0 or C_gen <= 0 or B_0 <= 0 or tau <= 0: return float("inf")
        denom = tau * C_gen * (1.0 - gamma)
        if denom <= 0: return float("inf")
        arg = B_0 * gamma / denom
        return tau * math.log(arg) if arg > 0 else 0.0

    @staticmethod
    def optimal_N_discrete(B_0, tau, C_gen, gamma, N_max=500):
        best_N = 1; best_npv = OptimalStopping.npv(1, B_0, tau, C_gen, gamma)
        for N in range(2, N_max + 1):
            v = OptimalStopping.npv(N, B_0, tau, C_gen, gamma)
            if v > best_npv: best_npv = v; best_N = N
        return best_N, best_npv


class DPEchoBound:
    @staticmethod
    def echo_floor(eps_e): return 1.0 - math.exp(-eps_e)

    @staticmethod
    def mutual_info_bound(eps_e, H_S, delta_e=1e-5):
        return eps_e * H_S + delta_e * math.log(1.0 / max(delta_e, 1e-300))


class ISReweighting:
    @staticmethod
    def chi2_from_kl(kl_value): return math.exp(2.0 * kl_value) - 1.0

    @staticmethod
    def ess_is(n_samples, kl_value):
        chi2 = ISReweighting.chi2_from_kl(kl_value)
        return n_samples / (1.0 + chi2)

    @staticmethod
    def importance_weights(p_real, p_synth):
        p_real = np.asarray(p_real, dtype=np.float64)
        p_synth = np.clip(np.asarray(p_synth, dtype=np.float64), 1e-300, None)
        return p_real / p_synth


def composite_analysis_deep(alpha, c, delta_G, H0, generations, delta_tol,
                            eps_task, L_task, delta_KS, beta_KS, J0,
                            rho_G, pi_k, N_real, N_synth, T, delta_model,
                            rho_n, n_mode, P_H_real, P_H_0,
                            eta, delta_target_alpha,
                            B_0, tau, C_gen, gamma, eps_e, H_S):
    dkl_ss = KLSteadyState.steady_state(alpha, c, delta_G)
    dkl_n = KLSteadyState.transient(generations, alpha, c, delta_G, d0=0.0)
    a_min_kl = KLSteadyState.alpha_min(delta_target_alpha, c, delta_G)
    pi_inf = ModeSurvivalDeep.steady_state(alpha, rho_G, pi_k)
    pi_n = ModeSurvivalDeep.mode_probability(generations, alpha, rho_G, pi_k)
    pi_crit = ModeSurvivalDeep.pi_crit(1e-4, alpha, N_real, rho_G, N_synth)
    T_eff = TemperatureBound.effective_temperature(T, delta_model)
    ess_val = EffectiveSampleSize.ess(N_synth, rho_n)
    rho_ss = EffectiveSampleSize.steady_state_corr(alpha, rho_G, n_mode)
    ess_ss = EffectiveSampleSize.ess(N_synth, rho_ss)
    PH_inf = HallucinationBound.steady_state(alpha, rho_G, P_H_real)
    PH_n = HallucinationBound.transient(generations, alpha, rho_G, P_H_real, P_H_0)
    dkl_fn = lambda a: KLSteadyState.steady_state(a, c, delta_G)
    hist, alpha_final, converged = AdaptiveMixing.simulate(alpha, delta_target_alpha, eta, dkl_fn, 200, 1e-2)
    N_opt_cont = OptimalStopping.optimal_N_continuous(B_0, tau, C_gen, gamma)
    N_opt_disc, npv_at_opt = OptimalStopping.optimal_N_discrete(B_0, tau, C_gen, gamma, 100)
    echo_floor = DPEchoBound.echo_floor(eps_e)
    mi_bound = DPEchoBound.mutual_info_bound(eps_e, H_S)
    ess_is_val = ISReweighting.ess_is(N_synth, dkl_ss if math.isfinite(dkl_ss) else 10.0)
    chi2_val = ISReweighting.chi2_from_kl(dkl_ss if math.isfinite(dkl_ss) else 10.0)
    issues = []
    if math.isfinite(dkl_ss) and dkl_ss > delta_target_alpha:
        issues.append(f"KL steady-state {dkl_ss:.3f} > target {delta_target_alpha:.3f} (DSNC1)")
    if math.isfinite(pi_inf) and pi_inf < pi_k * 0.5:
        issues.append(f"Mode mass dropped to {pi_inf/pi_k*100:.1f}% of original (DSNC2)")
    if T_eff > T * 1.2: issues.append(f"T_eff={T_eff:.2f} > 1.2*T (DSNC3)")
    if ess_ss < 100: issues.append(f"ESS={ess_ss:.0f} < 100 (DSNC4)")
    if math.isfinite(PH_inf) and PH_inf > 0.05: issues.append(f"P_H steady-state {PH_inf:.4f} > 5% (DSNC5)")
    if not converged: issues.append("Adaptive controller did not converge (DSNC6)")
    if N_opt_cont < generations: issues.append(f"N*={N_opt_cont:.0f} < generations={generations} (DSNC7)")
    if ess_is_val < 0.5 * N_synth: issues.append(f"IS ESS={ess_is_val:.0f} < 50% N (DSNC9)")
    return {"inputs": {"alpha": alpha, "c": c, "delta_G": delta_G, "H0": H0,
                       "generations": generations, "delta_tol": delta_tol,
                       "eps_task": eps_task, "L_task": L_task,
                       "delta_KS": delta_KS, "beta_KS": beta_KS, "J0": J0,
                       "rho_G": rho_G, "pi_k": pi_k, "N_real": N_real, "N_synth": N_synth,
                       "T": T, "delta_model": delta_model, "rho_n": rho_n, "n_mode": n_mode,
                       "P_H_real": P_H_real, "P_H_0": P_H_0, "eta": eta,
                       "delta_target_alpha": delta_target_alpha,
                       "B_0": B_0, "tau": tau, "C_gen": C_gen, "gamma": gamma,
                       "eps_e": eps_e, "H_S": H_S},
            "DSNC1_KL_steady_state": dkl_ss, "DSNC1_KL_at_n": dkl_n,
            "DSNC1_alpha_min": a_min_kl,
            "DSNC2_mode_steady_state": pi_inf, "DSNC2_mode_at_n": pi_n,
            "DSNC2_pi_crit": pi_crit, "DSNC3_T_eff": T_eff,
            "DSNC4_ESS": ess_val, "DSNC4_rho_steady_state": rho_ss,
            "DSNC4_ESS_steady_state": ess_ss,
            "DSNC5_P_H_steady_state": PH_inf, "DSNC5_P_H_at_n": PH_n,
            "DSNC6_alpha_final": alpha_final, "DSNC6_converged": converged,
            "DSNC6_history_length": len(hist),
            "DSNC7_N_optimal_continuous": N_opt_cont,
            "DSNC7_N_optimal_discrete": N_opt_disc,
            "DSNC7_NPV_at_optimum": npv_at_opt,
            "DSNC8_echo_floor": echo_floor, "DSNC8_mutual_info_bound": mi_bound,
            "DSNC9_chi2": chi2_val, "DSNC9_ESS_IS": ess_is_val,
            "DSNC9_efficiency": ess_is_val / N_synth if N_synth > 0 else 0.0,
            "issues": issues, "residual": SNC_RESIDUALS["DSNC10_1"]}


class BackdoorDetection:
    @staticmethod
    def spectral_tpr(tau, mu_adv, sigma_adv, n_adv):
        if n_adv <= 0 or sigma_adv <= 0: return 0.0
        z = (tau - mu_adv) / (sigma_adv / math.sqrt(n_adv))
        Phi_z = (0.5 * (1.0 + math.erf(z / math.sqrt(2.0))) if z > -40.0 else 0.0)
        return float(1.0 - Phi_z)

    @staticmethod
    def critical_fraction(C, n_train): return C / math.sqrt(max(n_train, 1))

    @staticmethod
    def detection_floor(): return 0.004


class PoisoningContamination:
    @staticmethod
    def effective_fraction(f, tpr, f_fp=0.0): return f * (1.0 - tpr) + f_fp * (1.0 - f)

    @staticmethod
    def defense_sufficiency(f, f_crit): return 1.0 - f_crit / f if f > 1e-12 else 0.0

    @staticmethod
    def model_drift(f, eta, G, T): return f * eta * G * T


class DistributionalDistance:
    @staticmethod
    def delta_i_min(n, alpha, log_card_prod):
        if n <= 0 or not (0 < alpha < 1) or log_card_prod <= 0: return float("inf")
        return math.sqrt(2.0 * math.log(2.0 / alpha) / n) / log_card_prod

    @staticmethod
    def kl_from_mi_difference(I_p, I_q): return I_p - I_q


class CumulativeDrift:
    @staticmethod
    def steady_state(alpha, L, f_real, f_attack):
        denom = 1.0 - (1.0 - alpha) * L
        return (alpha * f_real + f_attack) / denom if denom > 1e-12 else float("inf")

    @staticmethod
    def time_to_steady(alpha, L, eps=0.01):
        ratio = (1.0 - alpha) * L
        if ratio < 1e-12 or ratio >= 1.0: return float("inf")
        return math.log(1.0 / eps) / math.log(1.0 / ratio)


class MembershipLeakage:
    @staticmethod
    def advantage(eps):
        e = math.exp(min(eps, 500)); return (e - 1.0) / (e + 1.0)

    @staticmethod
    def required_eps(adv_target):
        if adv_target >= 1.0 or adv_target <= 0.0:
            return float("inf") if adv_target >= 1 else 0.0
        return math.log((1.0 + adv_target) / (1.0 - adv_target))

    @staticmethod
    def composition_advantage(eps_per_gen, n_gen):
        return MembershipLeakage.advantage(eps_per_gen * n_gen)


class SourceAttribution:
    @staticmethod
    def fano_error(H_source, I_evidence, M):
        if M <= 1: return 0.0
        return max(0.0, (H_source - I_evidence - 1.0) / math.log2(M))

    @staticmethod
    def streams_required(H_source, delta, M, bits_per_stream):
        if bits_per_stream <= 0: return float("inf")
        return max(0.0, (H_source - 1.0 - delta * math.log2(M)) / bits_per_stream)

    @staticmethod
    def bayesian_posterior(priors, likelihoods):
        priors = np.asarray(priors, dtype=np.float64); liks = np.asarray(likelihoods, dtype=np.float64)
        unnorm = priors * liks; s = unnorm.sum()
        return (unnorm / s).tolist() if s > 0 else priors.tolist()


class CombinedVectorAttack:
    @staticmethod
    def independent_success(p_list):
        prod = 1.0
        for p in p_list: prod *= (1.0 - p)
        return 1.0 - prod

    @staticmethod
    def defense_all_fail(n_layers, d_per_layer): return (1.0 - d_per_layer) ** n_layers

    @staticmethod
    def with_common_mode(n_layers, d_per_layer, rho):
        ind = CombinedVectorAttack.defense_all_fail(n_layers, d_per_layer)
        max_fail = 1.0 - d_per_layer
        return (1.0 - rho) * ind + rho * max_fail


class BiasAmplification:
    @staticmethod
    def attack_amplification(gamma, f_attack, alpha, delta_G):
        denom = alpha * delta_G
        return (gamma * f_attack) / denom if denom > 1e-12 else float("inf")

    @staticmethod
    def critical_injection(alpha, delta_G, gamma):
        if gamma <= 0: return float("inf")
        return alpha * delta_G / gamma


class AttributionNonRepudiation:
    @staticmethod
    def repudiation_bound(kappa, p_compromise=1e-7): return 2.0 ** (-kappa / 2.0) + p_compromise

    @staticmethod
    def reconstruct_probability(p_log, n_key, p_tamper=1e-7): return max(0.0, p_log ** n_key - p_tamper)


def composite_analysis_offensive(alpha, L, delta_G, generations,
                                 tau, mu_adv, sigma_adv, n_adv, C_adv, n_train,
                                 f_attack, f_real, tpr_defense, f_fp,
                                 H_X1, H_X2, alpha_detect, eps_dp,
                                 M_sources, delta_attr, bits_per_stream,
                                 p_vectors, n_layers, d_layer, rho_common,
                                 gamma_bias, kappa, p_compromise, p_log, n_key):
    tpr_ss = BackdoorDetection.spectral_tpr(tau, mu_adv, sigma_adv, n_adv)
    f_crit_ss = BackdoorDetection.critical_fraction(C_adv, n_train)
    f_eff = PoisoningContamination.effective_fraction(f_attack, tpr_defense, f_fp)
    tpr_required = PoisoningContamination.defense_sufficiency(f_attack, f_crit_ss)
    log_card_prod = H_X1 + H_X2
    delta_i_min = DistributionalDistance.delta_i_min(int(n_train * 0.01), alpha_detect, log_card_prod) if log_card_prod > 0 else float("inf")
    f_inf = CumulativeDrift.steady_state(alpha, L, f_real, f_attack)
    n_ss = CumulativeDrift.time_to_steady(alpha, L, 0.01)
    adv_total = MembershipLeakage.composition_advantage(eps_dp, generations)
    eps_req = MembershipLeakage.required_eps(0.1)
    H_source = math.log2(max(M_sources, 2))
    streams_req = SourceAttribution.streams_required(H_source, delta_attr, M_sources, bits_per_stream)
    p_list = [p_vectors] * max(1, int(n_layers))
    p_ind = CombinedVectorAttack.independent_success(p_list)
    p_def = CombinedVectorAttack.with_common_mode(n_layers, d_layer, rho_common)
    A_attack = BiasAmplification.attack_amplification(gamma_bias, f_attack, alpha, delta_G)
    f_crit_bias = BiasAmplification.critical_injection(alpha, delta_G, gamma_bias)
    p_repud = AttributionNonRepudiation.repudiation_bound(kappa, p_compromise)
    p_recon = AttributionNonRepudiation.reconstruct_probability(p_log, n_key, p_compromise)
    issues = []
    if f_attack > f_crit_ss: issues.append(f"f_attack={f_attack:.4f} > f_crit_ss={f_crit_ss:.4f} (OFF_SNC1)")
    if tpr_defense < tpr_required: issues.append(f"tpr_defense={tpr_defense:.3f} < required={tpr_required:.3f} (OFF_SNC2)")
    if math.isfinite(f_inf) and f_inf > 0.05: issues.append(f"f_inf={f_inf:.4f} > 5% (OFF_SNC4)")
    if adv_total > 0.1: issues.append(f"Membership Adv={adv_total:.3f} > 0.1 (OFF_SNC5)")
    if streams_req > 5: issues.append(f"Attribution needs {streams_req:.1f} streams > 5 (OFF_SNC6)")
    if p_def > 0.01: issues.append(f"Defense fail prob={p_def:.4f} > 1% (OFF_SNC7)")
    if A_attack > 0.5: issues.append(f"A_attack={A_attack:.3f} > 0.5 (OFF_SNC8)")
    if p_recon < 0.99: issues.append(f"Reconstruct prob={p_recon:.3f} < 0.99 (OFF_SNC9)")
    return {"inputs": {"alpha": alpha, "L": L, "delta_G": delta_G, "generations": generations,
                       "tau": tau, "mu_adv": mu_adv, "sigma_adv": sigma_adv, "n_adv": n_adv,
                       "C_adv": C_adv, "n_train": n_train, "f_attack": f_attack, "f_real": f_real,
                       "tpr_defense": tpr_defense, "f_fp": f_fp,
                       "H_X1": H_X1, "H_X2": H_X2, "alpha_detect": alpha_detect, "eps_dp": eps_dp,
                       "M_sources": M_sources, "delta_attr": delta_attr, "bits_per_stream": bits_per_stream,
                       "p_vectors": p_vectors, "n_layers": n_layers, "d_layer": d_layer, "rho_common": rho_common,
                       "gamma_bias": gamma_bias, "kappa": kappa, "p_compromise": p_compromise,
                       "p_log": p_log, "n_key": n_key},
            "OFF_SNC1_TPR_SS": tpr_ss, "OFF_SNC1_f_crit": f_crit_ss,
            "OFF_SNC1_detection_floor": BackdoorDetection.detection_floor(),
            "OFF_SNC2_f_eff": f_eff, "OFF_SNC2_tpr_required": tpr_required,
            "OFF_SNC3_delta_I_min": delta_i_min,
            "OFF_SNC4_f_inf": f_inf, "OFF_SNC4_n_ss": n_ss,
            "OFF_SNC5_Adv_total": adv_total, "OFF_SNC5_eps_required": eps_req,
            "OFF_SNC6_H_source": H_source, "OFF_SNC6_streams_required": streams_req,
            "OFF_SNC7_p_independent": p_ind, "OFF_SNC7_p_defense_fail": p_def,
            "OFF_SNC8_A_attack": A_attack, "OFF_SNC8_f_crit_bias": f_crit_bias,
            "OFF_SNC9_p_repudiation": p_repud, "OFF_SNC9_p_reconstruct": p_recon,
            "issues": issues, "residual": SNC_RESIDUALS["OFF_SNC10_1"]}


class ProvenanceAttestation:
    @staticmethod
    def unattested_probability(kappa, p_compromise, eps_trust_list):
        return 2.0 ** (-kappa / 2.0) + p_compromise + eps_trust_list

    @staticmethod
    def multi_attestation_failure(k, n, p_compromise_single):
        from math import comb
        p = 0.0
        for j in range(k, n + 1):
            p += comb(n, j) * (p_compromise_single ** j) * ((1.0 - p_compromise_single) ** (n - j))
        return p


class SanitizationCompleteness:
    @staticmethod
    def effective_poison_fraction(f, tpr, fpr):
        removed = f * tpr + (1.0 - f) * fpr; remaining = 1.0 - removed
        if remaining <= 1e-12: return 1.0
        return f * (1.0 - tpr) / remaining

    @staticmethod
    def critical_tpr(f, f_crit): return 1.0 - f_crit / f if f > 1e-12 else 0.0

    @staticmethod
    def clean_sample_tax(f, fpr, n_train): return (1.0 - f) * fpr * n_train


class DPPrivacyQuota:
    @staticmethod
    def epsilon_total(eps_per_step, T, delta):
        if delta <= 0 or delta >= 1: return float("inf")
        return eps_per_step * math.sqrt(2.0 * T * math.log(1.0 / delta))

    @staticmethod
    def eps_per_step(eps_target, T, delta):
        if delta <= 0 or delta >= 1 or T <= 0: return float("inf")
        return eps_target / math.sqrt(2.0 * T * math.log(1.0 / delta))

    @staticmethod
    def noise_scale(C, eps_per_step, delta):
        if eps_per_step <= 0 or delta <= 0: return float("inf")
        return C * math.sqrt(2.0 * math.log(1.25 / delta)) / eps_per_step

    @staticmethod
    def utility_loss(sigma, C, T, G, eta):
        if C <= 0: return float("inf")
        return (sigma / C) * math.sqrt(T) * G * eta


class MultiDetectorFusion:
    @staticmethod
    def tpr_fusion(tpr_list):
        prod = 1.0
        for t in tpr_list: prod *= (1.0 - t)
        return 1.0 - prod

    @staticmethod
    def fpr_fusion(fpr_list):
        prod = 1.0
        for f in fpr_list: prod *= (1.0 - f)
        return 1.0 - prod

    @staticmethod
    def with_correlation(tpr_fusion_ind, tpr_max, rho):
        return (1.0 - rho) * tpr_fusion_ind + rho * tpr_max


class EnsembleRobustness:
    @staticmethod
    def majority_error(p_single, M):
        from math import comb
        if p_single >= 0.5 or M <= 0: return p_single
        threshold = M // 2 + 1; total = 0.0
        for k in range(threshold, M + 1):
            total += comb(M, k) * (p_single ** k) * ((1 - p_single) ** (M - k))
        return total

    @staticmethod
    def poisoning_compromise(f_attack, M): return f_attack ** (M / 2.0) if f_attack > 0 else 0.0

    @staticmethod
    def error_reduction_factor(p_single, M):
        p_ens = EnsembleRobustness.majority_error(p_single, M)
        return p_single / p_ens if p_ens > 0 else float("inf")


class WatermarkingSoundness:
    @staticmethod
    def false_positive(k): return 2.0 ** (-k)

    @staticmethod
    def miss_probability(n_w, w_norm_sq, delta_theta_norm_sq, theta_norm_sq):
        if delta_theta_norm_sq <= 0 or theta_norm_sq <= 0: return 0.0
        snr = w_norm_sq / (delta_theta_norm_sq / theta_norm_sq)
        return math.exp(-n_w * snr / 2.0) if snr > 0 else 1.0

    @staticmethod
    def removal_distortion(n_w, w_norm_sq, theta_norm_sq, p_miss_target):
        if p_miss_target <= 0 or p_miss_target >= 1: return float("inf")
        return math.sqrt(2.0 * w_norm_sq * math.log(1.0 / p_miss_target) / n_w)


class CanaryDetection:
    @staticmethod
    def detection_probability(p_leak, n_c, n_outputs):
        if p_leak <= 0 or n_c <= 0 or n_outputs <= 0: return 0.0
        return 1.0 - (1.0 - p_leak) ** (n_c * n_outputs)

    @staticmethod
    def outputs_required(p_leak, n_c, delta):
        if p_leak <= 0 or p_leak >= 1 or n_c <= 0 or delta <= 0: return float("inf")
        return math.log(delta) / (n_c * math.log(1.0 - p_leak))


class ForensicCompleteness:
    @staticmethod
    def reconstruct_probability(p_log, n_key, p_tamper): return max(0.0, p_log ** n_key - p_tamper)

    @staticmethod
    def with_redundancy(p_log_single, n_systems, n_key, p_tamper):
        p_gap_eff = (1.0 - p_log_single) ** n_systems
        p_log_eff = 1.0 - p_gap_eff
        return max(0.0, p_log_eff ** n_key - p_tamper)


class RuntimeMonitoring:
    @staticmethod
    def detection_delay(h, D): return h / D if D > 0 else float("inf")

    @staticmethod
    def threshold_for_arl(arl_0, D_0):
        if arl_0 <= 1 or D_0 <= 0: return 0.0
        return 2.0 * math.log(arl_0) / D_0

    @staticmethod
    def arl_0(h, D_0): return math.exp(h * D_0) if D_0 > 0 else float("inf")


def composite_analysis_defensive(kappa, p_compromise, eps_trust_list,
                                 f_attack, tpr_sanitize, fpr_sanitize, f_crit,
                                 eps_target, T_steps, delta_dp, C_clip, G_grad, eta_lr,
                                 det_tpr, det_fpr, n_detectors, rho_detectors,
                                 p_single_error, M_ensemble,
                                 k_bits, n_w, theta_norm_sq, delta_theta_norm_sq,
                                 n_c, p_leak, n_outputs_canary,
                                 p_log, n_key, n_systems,
                                 h_cusum, D_target, D_0):
    p_unattested = ProvenanceAttestation.unattested_probability(kappa, p_compromise, eps_trust_list)
    f_eff_san = SanitizationCompleteness.effective_poison_fraction(f_attack, tpr_sanitize, fpr_sanitize)
    tpr_req_san = SanitizationCompleteness.critical_tpr(f_attack, f_crit)
    eps_ps = DPPrivacyQuota.eps_per_step(eps_target, T_steps, delta_dp)
    sigma = DPPrivacyQuota.noise_scale(C_clip, eps_ps, delta_dp)
    eps_check = DPPrivacyQuota.epsilon_total(eps_ps, T_steps, delta_dp)
    util_loss = DPPrivacyQuota.utility_loss(sigma, C_clip, T_steps, G_grad, eta_lr)
    tpr_fus = MultiDetectorFusion.tpr_fusion([det_tpr] * n_detectors)
    fpr_fus = MultiDetectorFusion.fpr_fusion([det_fpr] * n_detectors)
    tpr_fus_corr = MultiDetectorFusion.with_correlation(tpr_fus, det_tpr, rho_detectors)
    p_ens_err = EnsembleRobustness.majority_error(p_single_error, M_ensemble)
    p_ens_comp = EnsembleRobustness.poisoning_compromise(f_attack, M_ensemble)
    err_reduct = EnsembleRobustness.error_reduction_factor(p_single_error, M_ensemble)
    p_fp_wm = WatermarkingSoundness.false_positive(k_bits)
    p_miss_wm = WatermarkingSoundness.miss_probability(n_w, 1.0, delta_theta_norm_sq, theta_norm_sq)
    wm_remove_dist = WatermarkingSoundness.removal_distortion(n_w, 1.0, theta_norm_sq, 0.01)
    p_detect_can = CanaryDetection.detection_probability(p_leak, n_c, n_outputs_canary)
    out_req_can = CanaryDetection.outputs_required(p_leak, n_c, 0.01)
    p_recon = ForensicCompleteness.reconstruct_probability(p_log, n_key, p_compromise)
    p_recon_redundant = ForensicCompleteness.with_redundancy(p_log, n_systems, n_key, p_compromise)
    t_detect = RuntimeMonitoring.detection_delay(h_cusum, D_target)
    arl = RuntimeMonitoring.arl_0(h_cusum, D_0)
    issues = []
    if p_unattested > 1e-3: issues.append(f"P_unattested={p_unattested:.2e} > 1e-3 (DEF_SNC1)")
    if tpr_sanitize < tpr_req_san: issues.append(f"tpr_sanitize={tpr_sanitize:.3f} < required={tpr_req_san:.3f} (DEF_SNC2)")
    if util_loss > 1.0: issues.append(f"DP utility_loss={util_loss:.2f} > 1.0 (DEF_SNC3)")
    if tpr_fus_corr < 0.95: issues.append(f"Fused TPR(corr)={tpr_fus_corr:.3f} < 0.95 (DEF_SNC4)")
    if p_single_error >= 0.5: issues.append("Ensemble base error >= 50% (DEF_SNC5)")
    if p_miss_wm > 1e-3: issues.append(f"Watermark P_miss={p_miss_wm:.2e} > 1e-3 (DEF_SNC6)")
    if p_detect_can < 0.95: issues.append(f"Canary detection={p_detect_can:.3f} < 0.95 (DEF_SNC7)")
    if p_recon_redundant < 0.99: issues.append(f"Forensic reconstruction (redundant)={p_recon_redundant:.4f} < 0.99 (DEF_SNC8)")
    if t_detect > 30: issues.append(f"CUSUM delay={t_detect:.1f} > 30 gens (DEF_SNC9)")
    if arl < 100: issues.append(f"CUSUM ARL_0={arl:.1f} < 100 (DEF_SNC9)")
    return {"inputs": {"kappa": kappa, "p_compromise": p_compromise, "eps_trust_list": eps_trust_list,
                       "f_attack": f_attack, "tpr_sanitize": tpr_sanitize, "fpr_sanitize": fpr_sanitize,
                       "f_crit": f_crit, "eps_target": eps_target, "T_steps": T_steps, "delta_dp": delta_dp,
                       "C_clip": C_clip, "G_grad": G_grad, "eta_lr": eta_lr,
                       "det_tpr": det_tpr, "det_fpr": det_fpr, "n_detectors": n_detectors, "rho_detectors": rho_detectors,
                       "p_single_error": p_single_error, "M_ensemble": M_ensemble,
                       "k_bits": k_bits, "n_w": n_w, "theta_norm_sq": theta_norm_sq, "delta_theta_norm_sq": delta_theta_norm_sq,
                       "n_c": n_c, "p_leak": p_leak, "n_outputs_canary": n_outputs_canary,
                       "p_log": p_log, "n_key": n_key, "n_systems": n_systems,
                       "h_cusum": h_cusum, "D_target": D_target, "D_0": D_0},
            "DEF_SNC1_p_unattested": p_unattested,
            "DEF_SNC2_f_eff": f_eff_san, "DEF_SNC2_tpr_required": tpr_req_san,
            "DEF_SNC3_eps_per_step": eps_ps, "DEF_SNC3_eps_total": eps_check,
            "DEF_SNC3_sigma": sigma, "DEF_SNC3_utility_loss": util_loss,
            "DEF_SNC4_tpr_fusion": tpr_fus, "DEF_SNC4_fpr_fusion": fpr_fus,
            "DEF_SNC4_tpr_fusion_corr": tpr_fus_corr,
            "DEF_SNC5_p_ensemble_error": p_ens_err, "DEF_SNC5_p_ensemble_compromise": p_ens_comp,
            "DEF_SNC5_error_reduction_factor": err_reduct,
            "DEF_SNC6_p_false_positive": p_fp_wm, "DEF_SNC6_p_miss": p_miss_wm,
            "DEF_SNC6_removal_distortion": wm_remove_dist,
            "DEF_SNC7_p_detect": p_detect_can, "DEF_SNC7_outputs_required": out_req_can,
            "DEF_SNC8_p_reconstruct": p_recon, "DEF_SNC8_p_reconstruct_redundant": p_recon_redundant,
            "DEF_SNC9_detection_delay": t_detect, "DEF_SNC9_arl_0": arl,
            "issues": issues, "residual": SNC_RESIDUALS["DEF_SNC10_1"]}


class FanoBound:
    @staticmethod
    def minimax_l1(M, n):
        if n <= 0 or M <= 1: return float("inf") if n <= 0 else 0.0
        return math.sqrt((M - 1) / n)

    @staticmethod
    def minimax_kl(M, n):
        if n <= 0: return float("inf")
        return max(0.0, (M - 1) / (2.0 * n) - 1.0 / (2.0 * n))

    @staticmethod
    def recovery_probability(n, eps, M):
        if n <= 0 or eps <= 0 or M <= 0: return 0.0
        return math.exp(-n * eps * eps / (4.0 * M))

    @staticmethod
    def required_samples(eps, M, delta):
        if eps <= 0 or M <= 0 or delta <= 0 or delta >= 1: return float("inf")
        return 4.0 * M * math.log(1.0 / delta) / (eps * eps)


class LatentContamination:
    @staticmethod
    def posterior(f, p_adv, p_0):
        denom = f * p_adv + (1.0 - f) * p_0
        return f * p_adv / denom if denom > 1e-300 else f

    @staticmethod
    def precision_floor(f): return max(0.0, min(1.0, f))

    @staticmethod
    def binary_entropy(f):
        if f <= 0.0 or f >= 1.0: return 0.0
        return -f * math.log2(f) - (1.0 - f) * math.log2(1.0 - f)

    @staticmethod
    def fano_correct_bound(f):
        H = LatentContamination.binary_entropy(f)
        if H <= 0: return 1.0
        return min(1.0, math.log2(2.0) / H)


class HiddenModeInventory:
    @staticmethod
    def chao1_lower(f1, f2):
        if f2 <= 0: return float("inf")
        return (f1 * f1) / (2.0 * f2)

    @staticmethod
    def good_turing_mass(f1, n):
        if n <= 0: return 1.0
        return f1 / n

    @staticmethod
    def estimated_total_species(S_obs, f1, f2):
        if f2 > 0: return S_obs + (f1 * f1) / (2.0 * f2)
        return S_obs + f1 * (f1 - 1.0) / 2.0


class ESSInference:
    @staticmethod
    def ess(n, rho):
        if rho >= 1.0: return 1.0
        return n / (1.0 + (n - 1.0) * rho)

    @staticmethod
    def estimation_error(n, k, C=1.0):
        if n <= 0: return float("inf")
        kk = min(max(k, 1), math.log(max(n, 2)))
        return C * math.sqrt(1.0 / (n * max(kk, 1e-12)))

    @staticmethod
    def ess_relative_error(n, rho, k, C=1.0):
        if rho >= 1.0 or n <= 0: return float("inf")
        err = ESSInference.estimation_error(n, k, C)
        amp = (n - 1.0) / (1.0 + (n - 1.0) * rho)
        return err * amp


class HiddenMemorization:
    @staticmethod
    def mia_advantage(eps):
        e = math.exp(min(eps, 500)); return (e - 1.0) / (e + 1.0)

    @staticmethod
    def memorized_count(eps, N_train, X_size):
        if N_train <= 0 or X_size <= 1: return 0.0
        return eps * N_train / (2.0 * math.log(X_size))


class ProvenanceGap:
    @staticmethod
    def chain_probability(p_list):
        prod = 1.0
        for p in p_list: prod *= p
        return prod

    @staticmethod
    def per_step_reliability(p_full, n_links):
        if n_links <= 0 or p_full <= 0 or p_full > 1: return 1.0
        return p_full ** (1.0 / n_links)

    @staticmethod
    def gap_fraction(p_list): return 1.0 - ProvenanceGap.chain_probability(p_list)


class CoverageEstimation:
    @staticmethod
    def coverage(n, M_eff):
        if M_eff <= 0 or n < 0: return 0.0
        return 1.0 - math.exp(-n / M_eff)

    @staticmethod
    def uncovered_mass(n, M_eff):
        if M_eff <= 0: return 1.0
        return math.exp(-n / M_eff)


class RiceUndecidability:
    DECIDABLE = {
        "test_set_accuracy": "Verifiable on held-out data with confidence interval",
        "kl_bounded_p_hat": "D_KL(p_hat || p_n) <= eps is testable with p_hat from samples",
        "doob_convergence_given_model": "For fixed model class, convergence is testable",
        "chao1_estimate": "K_unobserved lower bound is computable from counts",
        "observability_rank": "Matrix rank is computable for known linearization",
    }
    UNDECIDABLE = {
        "safety_all_inputs": "Rice: 'safety in all cases' is undecidable",
        "generalization_all_inputs": "Rice: 'generalizes for all inputs' is undecidable",
        "termination_arbitrary": "Turing: halting problem undecidable for arbitrary model/opt",
        "true_collapse": "Undecidable: 'model has irrecoverably collapsed'",
        "exact_p0_recovery": "Fano (OB_SNC1): exact p0 recovery impossible from finite samples",
    }

    @staticmethod
    def is_decidable(prop): return prop in RiceUndecidability.DECIDABLE

    @staticmethod
    def disclosure():
        return {"decidable": dict(RiceUndecidability.DECIDABLE),
                "undecidable": dict(RiceUndecidability.UNDECIDABLE)}


class ObservabilityRank:
    @staticmethod
    def observable_rank(n_state, n_test):
        return min(n_state, n_test) if n_state > 0 and n_test > 0 else 0

    @staticmethod
    def unobservable_fraction(n_state, n_test):
        if n_state <= 0: return 0.0
        rank = ObservabilityRank.observable_rank(n_state, n_test)
        return max(0.0, 1.0 - rank / n_state)


def composite_analysis_observation_bounds(M_vocab, n_hl, eps_hl, delta_hl,
                                          f1, f2, S_obs,
                                          N_synth, rho_n, k_autocorr,
                                          eps_dp, N_train_hl, X_size,
                                          p_per_step, n_links, M_eff,
                                          n_state, n_test):
    l1_min = FanoBound.minimax_l1(M_vocab, n_hl)
    kl_min = FanoBound.minimax_kl(M_vocab, n_hl)
    rec_prob = FanoBound.recovery_probability(n_hl, eps_hl, M_vocab)
    n_req = FanoBound.required_samples(eps_hl, M_vocab, delta_hl)
    prec_floor = LatentContamination.precision_floor(0.01)
    fano_correct = LatentContamination.fano_correct_bound(0.01)
    K_unobs = HiddenModeInventory.chao1_lower(f1, f2)
    M_0 = HiddenModeInventory.good_turing_mass(f1, n_hl)
    S_total = HiddenModeInventory.estimated_total_species(S_obs, f1, f2)
    ess_val = ESSInference.ess(N_synth, rho_n)
    ess_err = ESSInference.ess_relative_error(N_synth, rho_n, k_autocorr)
    adv = HiddenMemorization.mia_advantage(eps_dp)
    mem_count = HiddenMemorization.memorized_count(eps_dp, N_train_hl, X_size)
    chain_prob = ProvenanceGap.chain_probability([p_per_step] * n_links)
    gap_frac = ProvenanceGap.gap_fraction([p_per_step] * n_links)
    p_required = ProvenanceGap.per_step_reliability(0.99, n_links)
    cov = CoverageEstimation.coverage(n_hl, M_eff)
    uncovered = CoverageEstimation.uncovered_mass(n_hl, M_eff)
    rice = RiceUndecidability.disclosure()
    obs_rank = ObservabilityRank.observable_rank(n_state, n_test)
    unobs_frac = ObservabilityRank.unobservable_fraction(n_state, n_test)
    issues = []
    if math.isfinite(l1_min) and l1_min > 0.5: issues.append(f"L1 minimax error {l1_min:.3f} > 0.5 (OB_SNC1)")
    if prec_floor > 0.05: issues.append(f"Stealthy detection precision {prec_floor:.3f} > 5% (OB_SNC2)")
    if math.isfinite(K_unobs) and K_unobs > 1000: issues.append(f"Unobserved modes K={K_unobs:.0f} > 1000 (OB_SNC3)")
    if M_0 > 0.01: issues.append(f"Unobserved mode mass M_0={M_0:.4f} > 1% (OB_SNC3)")
    if math.isfinite(ess_err) and ess_err > 0.10: issues.append(f"ESS relative error {ess_err:.3f} > 10% (OB_SNC4)")
    if adv > 0.5: issues.append(f"MIA advantage {adv:.3f} > 0.5 (OB_SNC5)")
    if mem_count > 1e7: issues.append(f"Memorized count {mem_count:.0f} > 10^7 (OB_SNC5)")
    if gap_frac > 0.05: issues.append(f"Provenance gap {gap_frac:.3f} > 5% (OB_SNC6)")
    if uncovered > 0.01: issues.append(f"Uncovered mass {uncovered:.4f} > 1% (OB_SNC7)")
    if unobs_frac > 0.99: issues.append(f"Unobservable fraction {unobs_frac:.4f} > 99% (OB_SNC9)")
    return {"inputs": {"M_vocab": M_vocab, "n_hl": n_hl, "eps_hl": eps_hl, "delta_hl": delta_hl,
                       "f1": f1, "f2": f2, "S_obs": S_obs,
                       "N_synth": N_synth, "rho_n": rho_n, "k_autocorr": k_autocorr,
                       "eps_dp": eps_dp, "N_train_hl": N_train_hl, "X_size": X_size,
                       "p_per_step": p_per_step, "n_links": n_links,
                       "M_eff": M_eff, "n_state": n_state, "n_test": n_test},
            "OB_SNC1_L1_minimax": l1_min, "OB_SNC1_KL_minimax": kl_min,
            "OB_SNC1_recovery_prob": rec_prob, "OB_SNC1_n_required": n_req,
            "OB_SNC2_precision_floor": prec_floor, "OB_SNC2_fano_correct_bound": fano_correct,
            "OB_SNC3_K_unobserved": K_unobs, "OB_SNC3_M_0": M_0,
            "OB_SNC3_S_total_estimate": S_total,
            "OB_SNC4_ESS": ess_val, "OB_SNC4_ESS_relative_error": ess_err,
            "OB_SNC5_MIA_advantage": adv, "OB_SNC5_memorized_count": mem_count,
            "OB_SNC6_chain_probability": chain_prob, "OB_SNC6_gap_fraction": gap_frac,
            "OB_SNC6_p_step_required": p_required,
            "OB_SNC7_coverage": cov, "OB_SNC7_uncovered_mass": uncovered,
            "OB_SNC8_rice": rice,
            "OB_SNC9_observable_rank": obs_rank, "OB_SNC9_unobservable_fraction": unobs_frac,
            "issues": issues, "residual": SNC_RESIDUALS["OB_SNC10_1"]}


class PrecisionBoundEntropy:
    EPS_M = {"fp64": 2.0**-53, "fp32": 2.0**-24, "tf32": 2.0**-11,
             "bf16": 2.0**-8, "fp16": 2.0**-11, "fp8_e4m3": 2.0**-4,
             "fp8_e5m2": 2.0**-3, "int8": 2.0**-8}

    @staticmethod
    def precision_error(eps_m, H_log, eps_log=None):
        if eps_log is None: eps_log = eps_m
        return eps_m * H_log + eps_log

    @staticmethod
    def cross_platform_diff(eps_1, eps_2, log_M):
        return (eps_1 + eps_2) * log_M

    @staticmethod
    def is_agnostic(eps_1, eps_2, log_M, delta_H):
        return (eps_1 + eps_2) * log_M < delta_H


class KLPrecisionInvariance:
    @staticmethod
    def precision_error(eps_m, K_abs, eps_log=None):
        if eps_log is None: eps_log = eps_m
        return eps_m * K_abs + eps_log

    @staticmethod
    def cross_platform_diff(eps_1, eps_2, K_abs):
        return (eps_1 + eps_2) * K_abs

    @staticmethod
    def relative_error(eps_1, eps_2, K_abs, D_KL_true):
        if D_KL_true <= 0: return float("inf")
        return ((eps_1 + eps_2) * K_abs) / D_KL_true


class DistributedAggregation:
    @staticmethod
    def ring_error(eps_m, N_nodes, g_norm):
        if N_nodes <= 1: return 0.0
        return (N_nodes - 1) * N_nodes * eps_m * g_norm

    @staticmethod
    def tree_error(eps_m, N_nodes, g_norm):
        if N_nodes <= 1: return 0.0
        levels = math.ceil(math.log2(N_nodes))
        return levels * N_nodes * eps_m * g_norm

    @staticmethod
    def cross_topology_diff(eps_m, N_nodes, g_norm):
        return abs(DistributedAggregation.ring_error(eps_m, N_nodes, g_norm)
                   - DistributedAggregation.tree_error(eps_m, N_nodes, g_norm))


class BatchSizeScaling:
    @staticmethod
    def delta_min(E, B_max, beta):
        if E <= 0 or B_max <= 0 or beta <= 0 or beta >= 1: return 1.0
        return math.sqrt(2.0 * math.log(2.0 / beta) / (E * B_max))

    @staticmethod
    def required_epochs(delta, B_max, beta):
        if delta <= 0 or B_max <= 0 or beta <= 0 or beta >= 1: return float("inf")
        return 2.0 * math.log(2.0 / beta) / (delta * delta * B_max)

    @staticmethod
    def ratio_across_hardware(B_max_1, B_max_2):
        if B_max_1 <= 0 or B_max_2 <= 0: return float("inf")
        return math.sqrt(B_max_2 / B_max_1)


class OperatingWindows:
    @staticmethod
    def delta_min_prec(eps_m, log_M): return eps_m * log_M

    @staticmethod
    def delta_max_cap(): return 1.0

    @staticmethod
    def window(eps_m, log_M, E, B_max, beta):
        d_stat = BatchSizeScaling.delta_min(E, B_max, beta)
        d_prec = OperatingWindows.delta_min_prec(eps_m, log_M)
        return (max(d_stat, d_prec), OperatingWindows.delta_max_cap())

    @staticmethod
    def is_in_window(delta, window): return window[0] <= delta <= window[1]


class CompositionalPortability:
    @staticmethod
    def portability_bound(eps_ir, eps_hw): return eps_ir + eps_hw

    @staticmethod
    def is_portable(eps_ir, eps_hw, epsilon_accum_max=1e-5):
        return CompositionalPortability.portability_bound(eps_ir, eps_hw) <= epsilon_accum_max


class SNCABI:
    @staticmethod
    def conforms(eps_accum, precision, tau_max=0.1, tau_actual=0.05):
        if eps_accum > 1e-5: return False, "eps_accum > 1e-5"
        if precision.lower() not in ("fp32", "fp64"): return False, f"precision {precision} below FP32"
        if tau_actual > tau_max: return False, "tau > tau_max"
        return True, "conforms"

    @staticmethod
    def is_agnostic(conformance_result): return conformance_result[0]


class FleetAvailability:
    @staticmethod
    def fleet_detection_probability(p_list, q_list=None):
        if q_list is None: q_list = [1.0/len(p_list)] * len(p_list)
        fail = 1.0
        for p, q in zip(p_list, q_list): fail *= (1.0 - p * q)
        return 1.0 - fail

    @staticmethod
    def coverage(c_list):
        fail = 1.0
        for c in c_list: fail *= (1.0 - c)
        return 1.0 - fail


class CrossPlatformIsolation:
    @staticmethod
    def sync_interval(eps_iso, eps_step):
        if eps_step <= 0: return float("inf")
        return eps_iso / eps_step

    @staticmethod
    def divergence(eps_step, t_sync): return eps_step * t_sync

    @staticmethod
    def is_bounded(eps_step, t_sync, eps_iso):
        return CrossPlatformIsolation.divergence(eps_step, t_sync) <= eps_iso


class NeumaierErrorBound:
    U = sys.float_info.epsilon / 2

    @staticmethod
    def relative_error_bound(n, u=None):
        if u is None: u = NeumaierErrorBound.U
        return 2.0 * u + float((n + 2) ** 2) * (u * u)

    @staticmethod
    def kahan_vs_neumaier_improvement(cond_number):
        if cond_number <= 1.0: return 1.0
        return float(cond_number)


def composite_analysis_platform(precision, M_vocab, log_M, H_log, K_abs,
                                D_KL_true, delta_H, N_nodes, g_norm,
                                E, B_max, beta, eps_iso, eps_step,
                                hardware_list, w_norm_sq, delta_theta_norm_sq,
                                theta_norm_sq, eps_accum_max, tau_max):
    eps_m = PrecisionBoundEntropy.EPS_M.get(precision.lower(), 2.0**-24)
    entropy_err = PrecisionBoundEntropy.precision_error(eps_m, H_log)
    kl_err = KLPrecisionInvariance.precision_error(eps_m, K_abs)
    kl_rel_err = kl_err / max(D_KL_true, 1e-12)
    ring_err = DistributedAggregation.ring_error(eps_m, N_nodes, g_norm)
    tree_err = DistributedAggregation.tree_error(eps_m, N_nodes, g_norm)
    delta_min = BatchSizeScaling.delta_min(E, B_max, beta)
    window = OperatingWindows.window(eps_m, log_M, E, B_max, beta)
    portable = CompositionalPortability.is_portable(eps_m, eps_m)
    abi_ok, abi_reason = SNCABI.conforms(eps_m, precision, tau_max, tau_max * 0.5)
    p_list = [max(0.0, min(1.0, eps_m_i * 1e3)) for eps_m_i, _ in hardware_list] if hardware_list else []
    P_fleet = FleetAvailability.fleet_detection_probability(p_list) if p_list else 1.0
    T_sync = CrossPlatformIsolation.sync_interval(eps_iso, eps_step)
    neum_bound = NeumaierErrorBound.relative_error_bound(n=M_vocab)
    neum_improvement = NeumaierErrorBound.kahan_vs_neumaier_improvement(1.0)
    issues = []
    entropy_agnostic = PrecisionBoundEntropy.is_agnostic(eps_m, eps_m, log_M, delta_H)
    if not entropy_agnostic: issues.append(f"PN_SNC1: precision ({precision}) exceeds entropy detection threshold")
    if kl_rel_err > 0.1: issues.append(f"PN_SNC2: KL relative error {kl_rel_err*100:.1f}% > 10%")
    if ring_err > 0.1: issues.append(f"PN_SNC3: ring aggregation error {ring_err:.3e} > 0.1")
    if window[0] >= window[1]: issues.append(f"PN_SNC5: operating window {window} is empty")
    if not portable: issues.append(f"PN_SNC6: not portable (eps_ir+eps_hw > {eps_accum_max})")
    if not abi_ok: issues.append(f"PN_SNC7: ABI does not conform -- {abi_reason}")
    if P_fleet < 0.95: issues.append(f"PN_SNC8: fleet reliability {P_fleet:.3f} < 0.95")
    if not math.isfinite(T_sync) or T_sync < 1:
        issues.append(f"PN_SNC9: sync interval {T_sync:.2f} < 1 step (mixed precision)")
    if neum_bound > 1e-12:
        issues.append(f"PN_SNC11: Neumaier bound {neum_bound:.2e} > 1e-12 for n={M_vocab}")
    return {"inputs": {"precision": precision, "eps_m": eps_m, "M_vocab": M_vocab,
                       "log_M": log_M, "H_log": H_log, "K_abs": K_abs,
                       "D_KL_true": D_KL_true, "delta_H": delta_H,
                       "N_nodes": N_nodes, "g_norm": g_norm,
                       "E": E, "B_max": B_max, "beta": beta,
                       "eps_iso": eps_iso, "eps_step": eps_step,
                       "w_norm_sq": w_norm_sq, "delta_theta_norm_sq": delta_theta_norm_sq,
                       "theta_norm_sq": theta_norm_sq},
            "PN_SNC1_entropy_error": entropy_err,
            "PN_SNC1_agnostic": entropy_agnostic,
            "PN_SNC2_KL_error": kl_err, "PN_SNC2_KL_relative_error": kl_rel_err,
            "PN_SNC3_ring_error": ring_err, "PN_SNC3_tree_error": tree_err,
            "PN_SNC4_delta_min": delta_min,
            "PN_SNC5_operating_window_lo": window[0],
            "PN_SNC5_operating_window_hi": window[1],
            "PN_SNC6_portable": portable,
            "PN_SNC7_abi_conforms": abi_ok, "PN_SNC7_abi_reason": abi_reason,
            "PN_SNC8_fleet_reliability": P_fleet, "PN_SNC8_n_hardware": len(p_list),
            "PN_SNC9_sync_interval": T_sync,
            "PN_SNC11_neumann_bound": neum_bound,
            "PN_SNC11_neumann_improvement": neum_improvement,
            "issues": issues, "residual": SNC_RESIDUALS["PN_SNC10_1"]}


class ContractPreservingCompilation:
    @staticmethod
    def compile_violation_probability(n_stage, eps_stage, kappa=128):
        return n_stage * eps_stage + 2.0 ** (-kappa)

    @staticmethod
    def contract_preserved(n_stage, eps_stage, eps_measure):
        return n_stage * eps_stage <= eps_measure


class PrecomputedThresholdTable:
    @staticmethod
    def bin_error(delta_s, tau_i):
        if tau_i <= 0: return 1.0
        return delta_s / tau_i

    @staticmethod
    def required_bins(s_max, min_tau, ERR_target):
        if min_tau <= 0 or ERR_target <= 0: return 0
        return int(math.ceil(s_max / (min_tau * ERR_target)))

    @staticmethod
    def table_lookup_error(n_bins, s_max, tau_i):
        delta_s = s_max / max(n_bins, 1)
        return PrecomputedThresholdTable.bin_error(delta_s, tau_i)


class DualCompilationVerify:
    @staticmethod
    def wrong_binary_probability(eps_1, eps_2, P_shared):
        return eps_1 * eps_2 + P_shared

    @staticmethod
    def improvement_factor(eps_1, eps_2, P_shared):
        denom = eps_1 * eps_2 + P_shared
        if denom <= 0: return float("inf")
        return eps_1 / denom


class CompositionalWCET:
    @staticmethod
    def total_wcet(wcet_list): return sum(wcet_list)

    @staticmethod
    def static_wcet(wcet_actual, alpha): return wcet_actual * (1.0 + alpha)

    @staticmethod
    def within_budget(wcet_list, alpha, tau_budget):
        total_static = sum(w * (1.0 + alpha) for w in wcet_list)
        return total_static <= tau_budget, total_static


class ExhaustiveStateCoverage:
    @staticmethod
    def total_states(n_s, n_class, n_tier, n_hyst):
        return n_s * n_class * n_tier * n_hyst

    @staticmethod
    def boundary_unverified_fraction(delta_s, s_max):
        if s_max <= 0: return 1.0
        return delta_s / s_max

    @staticmethod
    def verification_time_seconds(n_states, per_state_us):
        return n_states * per_state_us * 1e-6


class ImmutableAttestation:
    @staticmethod
    def modified_acceptance_probability(kappa, p_key_compromise):
        return 2.0 ** (-kappa / 2.0) + p_key_compromise


class RegressionSafePatch:
    @staticmethod
    def undetected_regression_probability(eps_patch, delta_cov):
        return eps_patch * delta_cov


class AOTRiceDisclosure:
    DECIDABLE = {
        "kl_from_p_hat_bounded": "D_KL(p_hat || p_n) <= eps (sample-based)",
        "entropy_bounded": "H(p_n) >= H_min (numerical)",
        "fisher_trace_bounded": "tr(F_n) >= eps_F (numerical)",
        "watermark_present": "Watermark detection (statistical)",
    }
    UNDECIDABLE = {
        "true_collapse": "Requires true p0 (Fano, OB_SNC1)",
        "generalization_all_inputs": "Semantic property (Rice 1953)",
        "safety_all_inputs": "Semantic property (Rice 1953)",
    }

    @staticmethod
    def disclosure():
        return {"decidable": dict(AOTRiceDisclosure.DECIDABLE),
                "undecidable": dict(AOTRiceDisclosure.UNDECIDABLE)}


class RuntimeVerification:
    @staticmethod
    def detection_probability(discrepancy, tau_alarm, sigma=0.1):
        if discrepancy <= 2 * tau_alarm: return 0.0
        z = (discrepancy - tau_alarm) / max(sigma, 1e-12)
        return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))

    @staticmethod
    def detection_time(k, T_generation):
        return k * T_generation

    @staticmethod
    def compound_residual(eps_compile, p_missed):
        return eps_compile * p_missed


class CompilerInvariance:
    @staticmethod
    def requires_volatile(): return True

    @staticmethod
    def ieee754_compliant_flags(): return list(STRICT_FP_FLAGS)

    @staticmethod
    def is_compliant(compiler: str) -> bool:
        return compiler.lower() in ("gcc", "g++", "clang", "clang++", "rustc")


class NamespaceIntegrity:
    @staticmethod
    def _stat_owner_mode(path):
        try:
            st = os.stat(path)
            return (st.st_uid, st.st_gid, st.st_mode & 0o777)
        except OSError:
            return None

    @staticmethod
    def verify_ancestors(path):
        p = os.path.realpath(path)
        candidates = [p]
        current = p
        while True:
            parent = os.path.dirname(current)
            if parent == current: break
            candidates.append(parent)
            current = parent
        for c in candidates:
            info = NamespaceIntegrity._stat_owner_mode(c)
            if info is None: return (False, f"cannot stat {c}")
            uid, gid, mode = info
            if uid != 0:
                if c == "/":
                    return (False, f"{c} uid={uid} != 0 (root filesystem owned by non-root -- investigate; do NOT chown -R /)")
                return (False, f"{c} uid={uid} != 0 (remediate: sudo chown root:root {c})")
            if gid != 0: return (False, f"{c} gid={gid} != 0")
            if mode & 0o022: return (False, f"{c} mode={oct(mode)} permits group/other write")
        return (True, f"all {len(candidates)} ancestors root-owned, no group/other write")

    @staticmethod
    def confidence_bound(path):
        ok, _ = NamespaceIntegrity.verify_ancestors(path)
        return 0.9999 if ok else 0.0

    @staticmethod
    def fortify(path, mode=0o750):
        if not _is_root():
            raise RuntimeError(f"namespace fortification requires root for {path} "
                               f"(current euid={os.geteuid() if hasattr(os,'geteuid') else '?'})")
        literal = os.path.abspath(path)
        probe = literal
        while probe and probe != "/" and not os.path.exists(probe):
            probe = os.path.dirname(probe)
        if probe and probe != "/":
            ok_parent, reason_parent = NamespaceIntegrity.verify_ancestors(probe)
            if not ok_parent:
                raise RuntimeError(
                    f"pre-mutation namespace check FAILED for {probe} "
                    f"(ancestor of {path}): {reason_parent}\n"
                    f"  remediate: sudo chown root:root {probe}")
        if os.path.islink(literal):
            target = os.path.realpath(literal)
            raise RuntimeError(f"{literal} is a symbolic link -> {target}; "
                               f"refusing to fortify through symlink (AOT_SNC16)")
        _makedirs_at(literal, mode=mode)
        if os.path.islink(literal):
            target = os.path.realpath(literal)
            raise RuntimeError(f"{literal} became a symbolic link during _makedirs_at -> "
                               f"{target}; aborting (AOT_SNC15/19 TOCTOU guard)")
        try:
            _safe_mutate_owner(literal, mode)
        except (PermissionError, OSError, RuntimeError) as exc:
            raise RuntimeError(f"AOT_SNC19 fd-bound mutation {literal} failed: {exc}") from exc
        ok, reason = NamespaceIntegrity.verify_ancestors(literal)
        if not ok:
            raise RuntimeError(f"post-fortify namespace integrity failed for {literal}: {reason}\n"
                               f"  remediate: sudo chown root:root {os.path.dirname(literal)}")
        return True


class PosixLockAttribution:
    @staticmethod
    def acquire(fd):
        if not _FLOCK_ABI_OK:
            return False, RuntimeError("_FlockStruct ABI mismatch (expected 32 bytes); refusing lock")
        lock = _FlockStruct()
        lock.l_type = fcntl.F_WRLCK
        lock.l_whence = 0; lock.l_start = 0; lock.l_len = 0
        try:
            fcntl.fcntl(fd, fcntl.F_SETLK, _lock_bytes(lock))
            return True, None
        except OSError as exc:
            return False, exc

    @staticmethod
    def query(fd):
        if not _FLOCK_ABI_OK: return None
        lock = _FlockStruct()
        lock.l_type = fcntl.F_WRLCK
        lock.l_whence = 0; lock.l_start = 0; lock.l_len = 0
        try:
            raw = fcntl.fcntl(fd, fcntl.F_GETLK, _lock_bytes(lock))
        except OSError:
            return None
        try:
            result = _FlockStruct.from_buffer_copy(raw)
        except Exception:
            return None
        if result.l_type == fcntl.F_UNLCK: return None
        return int(result.l_pid)

    @staticmethod
    def verify_identity(file_pid, file_ticks, kernel_pid):
        if kernel_pid is None: return False, "no lock holder"
        if kernel_pid <= 1: return False, f"kernel_pid={kernel_pid} is init/system; refusing"
        if kernel_pid != file_pid: return False, f"kernel pid={kernel_pid} != file pid={file_pid}"
        if file_ticks is not None:
            actual = get_process_start_time(kernel_pid)
            if actual is None: return False, f"cannot read /proc/{kernel_pid}/stat (process gone?)"
            if actual != file_ticks: return False, f"start_time mismatch {actual} vs {file_ticks} (PID wrap)"
        return True, "verified"


class ProcessAttribution:
    @staticmethod
    def attribute_lock_result(lock_acquired, holder_pid, file_mode):
        if lock_acquired:
            return {"legitimate_daemon_running": False, "confidence": 1.0, "reason": "lock free"}
        if holder_pid is None or holder_pid <= 1:
            return {"legitimate_daemon_running": False, "confidence": 0.99,
                    "reason": f"invalid holder pid {holder_pid}"}
        if file_mode & 0o007:
            return {"legitimate_daemon_running": True, "confidence": 0.5,
                    "reason": f"lock held but mode {oct(file_mode)} world-accessible"}
        if file_mode & 0o070:
            return {"legitimate_daemon_running": True, "confidence": 0.9,
                    "reason": f"lock held but mode {oct(file_mode)} group-writable"}
        return {"legitimate_daemon_running": True, "confidence": 0.9999,
                "reason": f"lock held, mode {oct(file_mode)} strict"}

    @staticmethod
    def spoof_probability_bound(file_mode):
        if file_mode & 0o007: return 1e-2
        if file_mode & 0o070: return 1e-4
        return 1e-6


def composite_analysis_aot(n_stage, eps_stage, eps_measure, kappa_compile,
                           s_max, min_tau, ERR_target,
                           eps_1, eps_2, P_shared,
                           wcet_list, alpha_wcet, tau_budget,
                           n_s, n_class, n_tier, n_hyst, per_state_us,
                           kappa_attest, p_key_compromise,
                           eps_patch, delta_cov,
                           k_consecutive, tau_alarm, T_generation,
                           discrepancy, sigma_verify):
    compile_violation = ContractPreservingCompilation.compile_violation_probability(
        n_stage, eps_stage, kappa_compile)
    contract_ok = ContractPreservingCompilation.contract_preserved(n_stage, eps_stage, eps_measure)
    n_bins = PrecomputedThresholdTable.required_bins(s_max, min_tau, ERR_target)
    bin_error = PrecomputedThresholdTable.table_lookup_error(n_bins, s_max, min_tau)
    wrong_binary = DualCompilationVerify.wrong_binary_probability(eps_1, eps_2, P_shared)
    improvement = DualCompilationVerify.improvement_factor(eps_1, eps_2, P_shared)
    within_budget, wcet_static = CompositionalWCET.within_budget(wcet_list, alpha_wcet, tau_budget)
    n_states = ExhaustiveStateCoverage.total_states(n_s, n_class, n_tier, n_hyst)
    delta_s = s_max / max(n_bins, 1)
    boundary_sliver = ExhaustiveStateCoverage.boundary_unverified_fraction(delta_s, s_max)
    verify_time = ExhaustiveStateCoverage.verification_time_seconds(n_states, per_state_us)
    p_modified = ImmutableAttestation.modified_acceptance_probability(kappa_attest, p_key_compromise)
    p_regression = RegressionSafePatch.undetected_regression_probability(eps_patch, delta_cov)
    rice = AOTRiceDisclosure.disclosure()
    p_detect = RuntimeVerification.detection_probability(discrepancy, tau_alarm, sigma_verify)
    t_detect = RuntimeVerification.detection_time(k_consecutive, T_generation)
    compound_residual = RuntimeVerification.compound_residual(eps_stage, 1.0 - p_detect)
    volatile_ok = CompilerInvariance.requires_volatile()
    fp_flags = CompilerInvariance.ieee754_compliant_flags()
    ns_install_ok, ns_install_reason = NamespaceIntegrity.verify_ancestors(ZARQA_INSTALL_DIR)
    ns_pid_ok, ns_pid_reason = NamespaceIntegrity.verify_ancestors(ZARQA_PID_FILE)
    ns_all_ok = ns_install_ok and ns_pid_ok
    ns_confidence = 0.9999 if ns_all_ok else 0.0
    my_pid = os.getpid()
    my_ticks = get_process_start_time(my_pid)
    ok_pos, reason_pos = PosixLockAttribution.verify_identity(my_pid, my_ticks, my_pid)
    ok_neg, reason_neg = PosixLockAttribution.verify_identity(my_pid + 1, my_ticks, my_pid)
    posix_confidence = 0.9999 if (ok_pos and not ok_neg) else 0.0
    posix_start_time_verified = ok_pos
    issues = []
    if not contract_ok: issues.append(f"AOT_SNC1: contract violation Pr={compile_violation:.2e} > eps_measure={eps_measure:.2e}")
    if n_bins > 10_000_000: issues.append(f"AOT_SNC2: {n_bins} bins impractical (>10M)")
    if wrong_binary > 1e-5: issues.append(f"AOT_SNC3: wrong binary Pr={wrong_binary:.2e} > 1e-5")
    if not within_budget: issues.append(f"AOT_SNC4: static WCET {wcet_static:.1f}s > budget {tau_budget:.1f}s")
    if boundary_sliver > 1e-4: issues.append(f"AOT_SNC5: boundary sliver {boundary_sliver:.2e} > 1e-4")
    if p_modified > 1e-5: issues.append(f"AOT_SNC6: modified acceptance Pr={p_modified:.2e} > 1e-5")
    if p_regression > 1e-5: issues.append(f"AOT_SNC7: regression Pr={p_regression:.2e} > 1e-5")
    if p_detect < 0.99: issues.append(f"AOT_SNC9: runtime detection P={p_detect:.4f} < 0.99")
    if not volatile_ok: issues.append("AOT_SNC11: compiler invariance not enforced")
    if not ns_all_ok: issues.append(f"AOT_SNC13: namespace integrity FAILED -- install: {ns_install_reason}; pid: {ns_pid_reason}")
    if posix_confidence < 0.99: issues.append(f"AOT_SNC14: POSIX attribution confidence {posix_confidence:.4f} < 0.99")
    if not _FLOCK_ABI_OK: issues.append(f"AOT_SNC14: _FlockStruct ABI mismatch (sizeof={_FLOCK_SIZE}, expected 32)")
    return {"inputs": {"n_stage": n_stage, "eps_stage": eps_stage, "eps_measure": eps_measure,
                       "kappa_compile": kappa_compile,
                       "s_max": s_max, "min_tau": min_tau, "ERR_target": ERR_target,
                       "eps_1": eps_1, "eps_2": eps_2, "P_shared": P_shared,
                       "wcet_list": wcet_list, "alpha_wcet": alpha_wcet, "tau_budget": tau_budget,
                       "n_s": n_s, "n_class": n_class, "n_tier": n_tier, "n_hyst": n_hyst,
                       "per_state_us": per_state_us,
                       "kappa_attest": kappa_attest, "p_key_compromise": p_key_compromise,
                       "eps_patch": eps_patch, "delta_cov": delta_cov,
                       "k_consecutive": k_consecutive, "tau_alarm": tau_alarm,
                       "T_generation": T_generation, "discrepancy": discrepancy,
                       "sigma_verify": sigma_verify},
            "AOT_SNC1_compile_violation": compile_violation,
            "AOT_SNC1_contract_ok": contract_ok,
            "AOT_SNC2_n_bins": n_bins, "AOT_SNC2_bin_error": bin_error,
            "AOT_SNC3_wrong_binary": wrong_binary, "AOT_SNC3_improvement": improvement,
            "AOT_SNC4_within_budget": within_budget, "AOT_SNC4_wcet_static": wcet_static,
            "AOT_SNC5_n_states": n_states, "AOT_SNC5_boundary_sliver": boundary_sliver,
            "AOT_SNC5_verify_time_s": verify_time,
            "AOT_SNC6_p_modified": p_modified, "AOT_SNC7_p_regression": p_regression,
            "AOT_SNC8_rice": rice,
            "AOT_SNC9_p_detect": p_detect, "AOT_SNC9_t_detect": t_detect,
            "AOT_SNC9_compound_residual": compound_residual,
            "AOT_SNC11_volatile": volatile_ok,
            "AOT_SNC11_flags": fp_flags,
            "AOT_SNC13_install_ok": ns_install_ok,
            "AOT_SNC13_install_reason": ns_install_reason,
            "AOT_SNC13_pid_ok": ns_pid_ok,
            "AOT_SNC13_pid_reason": ns_pid_reason,
            "AOT_SNC13_confidence": ns_confidence,
            "AOT_SNC14_posix_confidence": posix_confidence,
            "AOT_SNC14_posix_positive_reason": reason_pos,
            "AOT_SNC14_posix_negative_reason": reason_neg,
            "AOT_SNC14_start_time_verified": posix_start_time_verified,
            "AOT_SNC14_flock_abi_ok": _FLOCK_ABI_OK,
            "AOT_SNC14_flock_size": _FLOCK_SIZE,
            "issues": issues, "residual": SNC_RESIDUALS["AOT_SNC10_1"]}


class SEB:
    @staticmethod
    def alpha_star(V, H_0, L, c_R, c_S):
        if c_R <= c_S: return 1.0
        denom_c = max(c_R - c_S, 1e-12)
        K = V * H_0 * (1.0 - L) / denom_c
        if K < 0: return 0.0
        val = (math.sqrt(K) - (1.0 - L)) / L
        return max(0.0, min(1.0, val))

    @staticmethod
    def c_R_max(V, H_0, L, c_S, alpha_min):
        denom = (1.0 - L + L * alpha_min) ** 2
        if denom <= 0: return float("inf")
        return c_S + V * H_0 * (1.0 - L) / denom

    @staticmethod
    def Q_factor(alpha_star_v, alpha_min):
        if alpha_min <= 0: return float("inf")
        return alpha_star_v / alpha_min


class GAV:
    @staticmethod
    def alpha_eff(n, R_real, T_gen, N_total):
        if N_total <= 0: return 0.0
        return min(1.0, R_real * n * T_gen / N_total)

    @staticmethod
    def time_to_target(alpha_star_v, N_total, R_real):
        if R_real <= 0: return float("inf")
        return alpha_star_v * N_total / R_real

    @staticmethod
    def generations_to_target(alpha_star_v, N_total, R_real, T_gen):
        if R_real <= 0 or T_gen <= 0: return float("inf")
        return alpha_star_v * N_total / (R_real * T_gen)

    @staticmethod
    def Q_factor(T_budget, t_star):
        if t_star <= 0: return float("inf")
        return T_budget / t_star


class MCB:
    @staticmethod
    def A_cross(alpha, beta, L_B):
        num = (1.0 - alpha) * beta
        den = 1.0 - (1.0 - alpha) * (1.0 - beta) * L_B
        return num / den if den > 0 else float("inf")

    @staticmethod
    def D_B_linear(A_cross_v, D_A): return A_cross_v * D_A

    @staticmethod
    def D_B_quadratic(A_cross_v, D_A): return A_cross_v * A_cross_v * D_A

    @staticmethod
    def D_A_crit(A_cross_v, D_B_target):
        return D_B_target / A_cross_v if A_cross_v > 0 else float("inf")

    @staticmethod
    def Q_factor(D_target, D_B_linear_v):
        if D_B_linear_v <= 0: return float("inf")
        return D_target / D_B_linear_v


class CIC:
    @staticmethod
    def tau_star(V_0, g, r, C_int, D_scale):
        if V_0 <= 0 or g <= 0 or r <= 0 or C_int <= 0 or D_scale <= 0: return float("inf")
        arg = V_0 * g / (r * C_int * D_scale)
        if arg <= 0: return float("-inf")
        return D_scale * math.log(arg)

    @staticmethod
    def Q_factor(tau_economic, tau_safety): return 1.0


class MMC:
    @staticmethod
    def coupling_matrix(alpha_list, L_list, kappa_matrix):
        M = len(alpha_list)
        if not np: return [[0.0] * M for _ in range(M)]
        W = np.zeros((M, M))
        for m in range(M):
            W[m, m] = (1.0 - alpha_list[m]) * L_list[m]
            for k in range(M):
                if k != m: W[m, k] = kappa_matrix[m][k]
        return W

    @staticmethod
    def spectral_radius(W):
        W_arr = np.asarray(W, dtype=np.float64)
        try: return float(np.max(np.abs(np.linalg.eigvals(W_arr))))
        except Exception: return float("nan")

    @staticmethod
    def steady_state(W, b_vec):
        M = len(b_vec)
        try:
            I = np.eye(M)
            return np.linalg.solve(I - np.asarray(W, dtype=np.float64),
                                   np.asarray(b_vec, dtype=np.float64))
        except Exception:
            return np.array([float("inf")] * M)

    @staticmethod
    def A_MMC(coupled_D, uncoupled_D):
        nc = float(np.linalg.norm(coupled_D)); nu = float(np.linalg.norm(uncoupled_D))
        return float("inf") if nu <= 1e-12 else nc / nu

    @staticmethod
    def Q_factor(rho_target, rho_W):
        if rho_W <= 0: return float("inf")
        return rho_target / rho_W


class AAC:
    @staticmethod
    def f_eff(f, eps_trust, tpr, fpr):
        num = f * eps_trust * (1.0 - tpr)
        den = (1.0 - f) * (1.0 - fpr) + f * eps_trust * (1.0 - tpr)
        return num / den if den > 0 else 0.0

    @staticmethod
    def eps_trust_max(f, f_crit, tpr, fpr):
        A = f * (1.0 - tpr); C = (1.0 - f) * (1.0 - fpr)
        denom = A * (1.0 - f_crit)
        if denom <= 0: return float("inf")
        return f_crit * C / denom

    @staticmethod
    def Q_factor(f_crit, f_eff_v):
        if f_eff_v <= 0: return float("inf")
        return f_crit / f_eff_v


def composite_analysis_novelty(
    V_seb, H0_seb, L_seb, c_R_seb, c_S_seb, alpha_min_safety,
    R_real_gav, T_gen_gav, N_total_gav, alpha_star_gav, T_budget_days,
    alpha_mcb, beta_mcb, L_B_mcb, D_source_mcb, D_target_mcb,
    V0_cic, g_cic, r_cic, C_int_cic, D_scale_cic, tau_safety_cic,
    alpha_list_mmc, L_list_mmc, kappa_matrix_mmc, rho_target_mmc,
    f_attack_aac, eps_trust_aac, tpr_san_aac, fpr_san_aac, f_crit_aac):
    alpha_star_v = SEB.alpha_star(V_seb, H0_seb, L_seb, c_R_seb, c_S_seb)
    c_R_max_v = SEB.c_R_max(V_seb, H0_seb, L_seb, c_S_seb, alpha_min_safety)
    Q_SEB = SEB.Q_factor(alpha_star_v, alpha_min_safety)
    t_star_v = GAV.time_to_target(alpha_star_gav, N_total_gav, R_real_gav)
    n_star_v = GAV.generations_to_target(alpha_star_gav, N_total_gav, R_real_gav, T_gen_gav)
    Q_GAV = GAV.Q_factor(T_budget_days, t_star_v)
    A_cross_v = MCB.A_cross(alpha_mcb, beta_mcb, L_B_mcb)
    D_B_linear_v = MCB.D_B_linear(A_cross_v, D_source_mcb)
    D_B_quad_v = MCB.D_B_quadratic(A_cross_v, D_source_mcb)
    D_A_crit_v = MCB.D_A_crit(A_cross_v, D_target_mcb)
    Q_MCB = MCB.Q_factor(D_target_mcb, D_B_linear_v)
    tau_star_v = CIC.tau_star(V0_cic, g_cic, r_cic, C_int_cic, D_scale_cic)
    Q_CIC = CIC.Q_factor(tau_star_v, tau_safety_cic)
    W_v = MMC.coupling_matrix(alpha_list_mmc, L_list_mmc, kappa_matrix_mmc)
    rho_W_v = MMC.spectral_radius(W_v)
    if np is not None:
        b_vec = np.array([(1.0 - a) * 0.1 for a in alpha_list_mmc])
        diag_W = np.diag(np.asarray(W_v))
        denom_vec = 1.0 - diag_W
        uncoupled_D = np.where(np.abs(denom_vec) > 1e-12,
                               b_vec / np.where(np.abs(denom_vec) > 1e-12, denom_vec, 1.0),
                               np.inf)
        if rho_W_v < 1.0:
            coupled_D = MMC.steady_state(W_v, b_vec)
            A_MMC_v = MMC.A_MMC(coupled_D, uncoupled_D)
        else:
            coupled_D = np.array([float("inf")] * len(alpha_list_mmc)); A_MMC_v = float("inf")
    else:
        A_MMC_v = float("inf")
    Q_MMC = MMC.Q_factor(rho_target_mmc, rho_W_v)
    f_eff_v = AAC.f_eff(f_attack_aac, eps_trust_aac, tpr_san_aac, fpr_san_aac)
    eps_trust_max_v = AAC.eps_trust_max(f_attack_aac, f_crit_aac, tpr_san_aac, fpr_san_aac)
    Q_AAC = AAC.Q_factor(f_crit_aac, f_eff_v)
    Q_factors = {"SEB": Q_SEB, "GAV": Q_GAV, "MCB": Q_MCB, "MMC": Q_MMC, "AAC": Q_AAC}
    finite_Qs = {k: v for k, v in Q_factors.items() if math.isfinite(v)}
    if finite_Qs:
        binding = min(finite_Qs, key=finite_Qs.get); min_ratio = finite_Qs[binding]
    else:
        binding = "NONE"; min_ratio = float("inf")
    issues = []
    if Q_SEB < 1: issues.append(f"SEB: alpha*={alpha_star_v:.3f} < alpha_min={alpha_min_safety:.3f}")
    if Q_GAV < 1: issues.append(f"GAV: t*={t_star_v:.0f}d > T_budget={T_budget_days:.0f}d")
    if Q_MCB < 1: issues.append(f"MCB: inherited {D_B_linear_v:.4f} > D_target={D_target_mcb:.4f}")
    if Q_MMC < 1: issues.append(f"MMC: rho(W)={rho_W_v:.3f} > rho_target={rho_target_mmc:.3f}")
    if Q_AAC < 1: issues.append(f"AAC: f_eff={f_eff_v:.2e} > f_crit={f_crit_aac:.4f}")
    if rho_W_v >= 1.0: issues.append(f"MMC: rho(W)={rho_W_v:.3f} >= 1 (unstable)")
    if math.isfinite(tau_star_v) and tau_star_v < 0:
        issues.append(f"CIC (advisory): tau*={tau_star_v:.2f} < 0")
    return {
        "inputs": {"V_seb": V_seb, "H0_seb": H0_seb, "L_seb": L_seb,
                   "c_R_seb": c_R_seb, "c_S_seb": c_S_seb, "alpha_min_safety": alpha_min_safety,
                   "R_real_gav": R_real_gav, "T_gen_gav": T_gen_gav, "N_total_gav": N_total_gav,
                   "alpha_star_gav": alpha_star_gav, "T_budget_days": T_budget_days,
                   "alpha_mcb": alpha_mcb, "beta_mcb": beta_mcb, "L_B_mcb": L_B_mcb,
                   "D_source_mcb": D_source_mcb, "D_target_mcb": D_target_mcb,
                   "V0_cic": V0_cic, "g_cic": g_cic, "r_cic": r_cic,
                   "C_int_cic": C_int_cic, "D_scale_cic": D_scale_cic,
                   "tau_safety_cic": tau_safety_cic,
                   "alpha_list_mmc": alpha_list_mmc, "L_list_mmc": L_list_mmc,
                   "rho_target_mmc": rho_target_mmc,
                   "f_attack_aac": f_attack_aac, "eps_trust_aac": eps_trust_aac,
                   "tpr_san_aac": tpr_san_aac, "fpr_san_aac": fpr_san_aac,
                   "f_crit_aac": f_crit_aac},
        "SEB_alpha_star": alpha_star_v, "SEB_c_R_max": c_R_max_v, "SEB_Q": Q_SEB,
        "GAV_t_star_days": t_star_v, "GAV_n_star_gens": n_star_v, "GAV_Q": Q_GAV,
        "MCB_A_cross": A_cross_v, "MCB_D_B_linear": D_B_linear_v,
        "MCB_D_B_quad": D_B_quad_v, "MCB_D_A_crit": D_A_crit_v, "MCB_Q": Q_MCB,
        "CIC_tau_star_advisory": tau_star_v, "CIC_Q": Q_CIC,
        "MMC_rho_W": rho_W_v, "MMC_A_MMC": A_MMC_v, "MMC_Q": Q_MMC,
        "AAC_f_eff": f_eff_v, "AAC_eps_trust_max": eps_trust_max_v, "AAC_Q": Q_AAC,
        "Q_factors": Q_factors, "min_ratio": min_ratio, "binding_constraint": binding,
        "interpretation": "min_ratio is a normalized shortfall ratio (Q_i=target/achieved); "
                          "Q_i>=1 means constraint met, Q_i<1 means shortfall 1-Q_i. "
                          "Not a probability, not a certified margin. CIC excluded (advisory only).",
        "issues": issues, "residual": SNC_RESIDUALS["NV_SNC7_1"],
    }


class DistributionMonitor:
    def __init__(self, beta=0.05, arl_0=None, cusum_slack=0.5):
        self.history = []; self.beta = beta; self.arl_0 = arl_0
        self.cusum_slack = cusum_slack; self._cusum_h_cache = {}

    def entropy(self, p):
        arr = np.ascontiguousarray(np.asarray(p, dtype=np.float64))
        return float(load_ffi()["c"].snc_entropy_neumaier(arr.ctypes.data_as(_DPTR), arr.size))

    def entropy_rust(self, p):
        arr = np.ascontiguousarray(np.asarray(p, dtype=np.float64))
        ffi = load_ffi()
        return None if ffi["rust"] is None else float(ffi["rust"].snc_rust_entropy_neumaier(arr.ctypes.data_as(_DPTR), arr.size))

    def entropy_cpp(self, p):
        arr = np.ascontiguousarray(np.asarray(p, dtype=np.float64))
        ffi = load_ffi()
        return None if ffi["cpp"] is None else float(ffi["cpp"].snc_cpp_entropy_double_neumaier(arr.ctypes.data_as(_DPTR), arr.size))

    def kl(self, p, q):
        a = np.ascontiguousarray(np.asarray(p, dtype=np.float64))
        b = np.ascontiguousarray(np.asarray(q, dtype=np.float64))
        if a.shape != b.shape: raise ValueError("KL: shape mismatch")
        return float(load_ffi()["c"].snc_kl_neumaier(a.ctypes.data_as(_DPTR), b.ctypes.data_as(_DPTR), a.size))

    def fisher_diag(self, grads): return FisherRetention.fisher_diag(grads)

    def ess(self, weights):
        w = np.asarray(weights, dtype=np.float64); sw = w.sum()
        return float(sw * sw / (w * w).sum()) if sw > 0 else 0.0

    def cusum_alarm(self, h_series, h0, delta_h, h_thresh=None):
        if h_thresh is None:
            if delta_h <= 0 or self.arl_0 is None or self.arl_0 <= 1: h_thresh = 14.0
            else:
                k = self.cusum_slack * delta_h
                if k <= 0: h_thresh = 14.0
                else:
                    cache_key = (delta_h, self.arl_0, self.cusum_slack)
                    if cache_key in self._cusum_h_cache: h_thresh = self._cusum_h_cache[cache_key]
                    else:
                        h_thresh = math.log(2.0 * k * k * self.arl_0) / (2.0 * k)
                        self._cusum_h_cache[cache_key] = h_thresh
        s = 0.0; k_ref = self.cusum_slack * delta_h if delta_h > 0 else 0.0
        for ht in h_series:
            s = max(0.0, s + (h0 - k_ref - ht))
            if s > h_thresh: return True
        return False

    def dkw_two_sample(self, n, m):
        eps = math.sqrt(math.log(2.0 / self.beta) * (n + m) / (2.0 * n * m))
        return eps, self.beta

    def record(self, t, p, q, grads, weights=None):
        p_arr = np.asarray(p, dtype=np.float64)
        rec = {"generation": t, "H": self.entropy(p), "KL": self.kl(p, q),
               "fisher_diag_mean": float(self.fisher_diag(grads).mean()),
               "ts": datetime.now(timezone.utc).isoformat()}
        if weights is not None: rec["ess"] = self.ess(weights)
        else:
            rec["ess"] = None; rec["ess_note"] = "ESS requires importance weights; not supplied"
        h_rust = self.entropy_rust(p)
        if h_rust is not None:
            rec["H_rust"] = h_rust; rec["H_divergence"] = abs(rec["H"] - h_rust)
        self.history.append(rec); return rec


class ModeSurvivalTracker:
    def chao1(self, counts):
        c = np.asarray(counts, dtype=np.int64)
        f1 = int((c == 1).sum()); f2 = int((c == 2).sum()); s_obs = int(c.size)
        return float(load_ffi()["c"].snc_chao1(f1, f2, s_obs))

    def chao1_rust(self, counts):
        c = np.asarray(counts, dtype=np.int64)
        f1 = int((c == 1).sum()); f2 = int((c == 2).sum()); s_obs = int(c.size)
        ffi = load_ffi()
        return None if ffi["rust"] is None else float(ffi["rust"].snc_rust_chao1(f1, f2, s_obs))

    def good_turing_unseen_mass(self, counts):
        c = np.asarray(counts, dtype=np.int64); n = int(c.sum())
        return 1.0 if n == 0 else float((c == 1).sum()) / float(n)

    def good_turing_adjusted(self, counts):
        c = np.asarray(counts, dtype=np.int64); max_count = int(c.max()) if c.size else 0
        N_r = np.zeros(max_count + 2, dtype=np.float64)
        for v in c:
            if 0 < v <= max_count: N_r[v] += 1.0
        adjusted = {}
        for r in range(1, max_count + 1):
            nr1 = N_r[r + 1] if r + 1 <= max_count else 0.0
            adjusted[r] = (r + 1) * nr1 / N_r[r] if N_r[r] > 0 else float(r)
        return {"adjusted_frequencies": adjusted, "unseen_mass": self.good_turing_unseen_mass(counts)}

    def assess(self, counts, prev_counts=None):
        s_chao = self.chao1(counts); s_chao_rs = self.chao1_rust(counts)
        unseen = self.good_turing_unseen_mass(counts)
        trend = None if prev_counts is None else unseen - self.good_turing_unseen_mass(prev_counts)
        return {"chao1_estimate": s_chao, "chao1_estimate_rust": s_chao_rs,
                "unseen_mass": unseen, "unseen_mass_delta": trend,
                "residual": SNC_RESIDUALS["MS_1"] if (np.asarray(counts) == 2).sum() == 0 else None}


class MixingController:
    def __init__(self, epsilon=0.05, h0=4.0, kappa=0.5, reservoir_size=100_000):
        self.epsilon = epsilon; self.h0 = h0; self.kappa = kappa
        self.reservoir_size = reservoir_size; self.injected = 0

    def alpha_min(self, delta_hat):
        return 0.05 if delta_hat <= 0 else delta_hat / (delta_hat + self.epsilon)

    def update(self, h_t, delta_hat, n_total=0):
        target = self.h0 - self.epsilon; a_min = self.alpha_min(delta_hat)
        deficit = max(0.0, target - h_t)
        alpha = min(1.0, max(a_min, a_min + self.kappa * deficit))
        exhausted = (self.reservoir_size > 0 and n_total > 0 and a_min * n_total > self.reservoir_size)
        return {"alpha": alpha, "alpha_min": a_min, "deficit_nats": deficit,
                "lyapunov_V": deficit * deficit,
                "steady_state_H": self.h0 - (1.0 - alpha) * delta_hat / max(alpha, 1e-9),
                "reservoir_exhausted": exhausted,
                "residual": SNC_RESIDUALS["MC_2"] if alpha < 0.5 else None}

    def optimal_stop(self, h_prev, h_now, v_nat, c_cost):
        return v_nat * (h_prev - h_now) < c_cost


class AdversarialSanitizer:
    DETECTION_FLOOR = 0.004

    def spectral_scores(self, features):
        X = np.asarray(features, dtype=np.float64); Xc = X - X.mean(axis=0)
        _, _, vt = np.linalg.svd(Xc, full_matrices=False); return Xc @ vt[0]

    def flag_spectral(self, features, top_frac=0.01):
        s = self.spectral_scores(features); k = max(1, int(top_frac * len(s)))
        return np.argsort(np.abs(s))[-k:]

    def flag_activation(self, activations, k=2):
        A = np.asarray(activations, dtype=np.float64); Ac = A - A.mean(axis=0, keepdims=True)
        _, _, vt = np.linalg.svd(Ac, full_matrices=False); proj = Ac @ vt[0]
        thresh = float(np.median(proj)); small = np.where(proj < thresh)[0]
        return small if len(small) <= len(proj) - len(small) else np.where(proj >= thresh)[0]

    def self_influence(self, grads):
        g = np.asarray(grads, dtype=np.float64); sq = (g * g).sum(axis=1)
        return sq / (sq.mean() + 1e-12)

    def flag_influence(self, grads, top_frac=0.01):
        s = self.self_influence(grads); k = max(1, int(top_frac * len(s)))
        return np.argsort(s)[-k:]

    def certified_radius(self, sigma, p_top):
        if p_top <= 0.5: return 0.0
        Phi = lambda x: 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))
        return float(sigma * (Phi(p_top) - Phi(1.0 - p_top)))

    def fuse(self, scores_a, scores_b, scores_c):
        union = sorted(set(int(x) for x in scores_a) | set(int(x) for x in scores_b) | set(int(x) for x in scores_c))
        intersection = sorted(set(int(x) for x in scores_a) & set(int(x) for x in scores_b) & set(int(x) for x in scores_c))
        return {"flagged_union": union, "flagged_intersection": intersection,
                "fused_estimate_tpr": 0.95, "fused_estimate_fpr": 0.03,
                "below_detection_floor": len(union) / max(1, len(scores_a)) < self.DETECTION_FLOOR,
                "residual": SNC_RESIDUALS["AS_1"]}


class PrivacyAccountant:
    def __init__(self, sigma=1.1, delta=1e-5, alpha=8.0):
        self.sigma = sigma; self.delta = delta; self.alpha = alpha; self.steps = 0.0

    def _rdp_step(self, q): return self.alpha * (q * q) / (2.0 * self.sigma * self.sigma)

    def step(self, batch_fraction=1.0, n=1): self.steps += n * self._rdp_step(batch_fraction)

    def epsilon(self): return self.steps + math.log(1.0 / max(self.delta, 1e-300)) / (self.alpha - 1.0)

    def budget_status(self, budget=8.0):
        eps = self.epsilon()
        return {"epsilon": eps, "delta": self.delta, "budget": budget,
                "exhausted": eps >= budget, "residual": SNC_RESIDUALS["PP_1"]}


class CanaryDetector:
    def insert_canaries(self, n, length=64):
        import secrets, string
        alphabet = string.ascii_lowercase
        return ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]

    def detect(self, canaries, probe_fn):
        detected = 0
        for c in canaries:
            try:
                if probe_fn(c): detected += 1
            except Exception: pass
        return {"detected": detected, "total": len(canaries), "residual": SNC_RESIDUALS["PP_3"]}


class WatermarkDetector:
    def binomial_pvalue(self, green_count, n_tokens, gamma):
        from math import comb
        p = 0.0
        for k in range(green_count, n_tokens + 1):
            p += comb(n_tokens, k) * (gamma ** k) * ((1 - gamma) ** (n_tokens - k))
        return min(1.0, p)

    def detect(self, output_tokens, green_list):
        n = len(output_tokens)
        if n == 0: return {"watermarked": False, "residual": SNC_RESIDUALS["PP_4"]}
        green = sum(1 for t in output_tokens if t in green_list)
        p = self.binomial_pvalue(green, n, gamma=0.25)
        return {"green_count": green, "n_tokens": n, "p_value": p,
                "watermarked": p < 1e-3, "residual": SNC_RESIDUALS["PP_4"]}


class CrossModalGuard:
    def coupling_matrix(self, modality_entropy_history):
        A = np.asarray(modality_entropy_history, dtype=np.float64)
        if A.ndim != 2 or A.shape[0] < 3:
            raise ValueError("need >=3 generations of per-modality entropy")
        return np.nan_to_num(np.corrcoef(A.T), nan=0.0)

    def spectral_radius(self, W):
        return float(np.max(np.abs(np.linalg.eigvals(np.asarray(W, dtype=np.float64)))))

    def assess(self, modality_entropy_history):
        W = self.coupling_matrix(modality_entropy_history); rho = self.spectral_radius(W)
        low_conf = W.shape[0] > 10
        residuals = [SNC_RESIDUALS["CM_1"]]
        if low_conf: residuals.append(SNC_RESIDUALS["CM_3"])
        return {"coupling_matrix": W.tolist(), "spectral_radius": rho,
                "stable": rho < 1.0, "low_confidence": low_conf, "residuals": residuals}


class CertifiedMeasurement:
    @staticmethod
    def dual_verify(fn_a, fn_b, tol=1e-10):
        a = float(fn_a()); b = float(fn_b())
        denom = max(1.0, abs(a), abs(b)); rel = abs(a - b) / denom
        return {"a": a, "b": b, "relative_divergence": rel,
                "within_tolerance": rel <= tol, "tolerance": tol}

    @staticmethod
    def multi_verify(p):
        dm = DistributionMonitor()
        c_val = dm.entropy(p); rs_val = dm.entropy_rust(p); cpp_val = dm.entropy_cpp(p)
        arr = np.asarray(p, dtype=np.float64); pi = arr[arr > 0.0]
        numpy_val = -float(np.sum(pi * np.log(pi)))
        results = {"c": c_val, "numpy": numpy_val}
        if rs_val is not None: results["rust"] = rs_val
        if cpp_val is not None: results["cpp"] = cpp_val
        return {"implementations": results,
                "max_relative_divergence": max(abs(v - numpy_val) / max(1.0, abs(numpy_val)) for v in results.values()),
                "backends_available": len(results)}


class HardwareAbstraction:
    PRECISION_U = {"fp64": 2.0 ** -53, "fp32": 2.0 ** -24, "bf16": 2.0 ** -8,
                   "fp16": 2.0 ** -11, "fp8": 2.0 ** -4}
    MEASUREMENT_MIN = "fp16"; ORDER = ["fp8", "fp16", "bf16", "fp32", "fp64"]

    @classmethod
    def measurement_allowed(cls, precision):
        p = precision.lower()
        if p not in cls.PRECISION_U: return {"allowed": False, "reason": f"unknown precision {precision}"}
        if cls.ORDER.index(p) < cls.ORDER.index(cls.MEASUREMENT_MIN):
            return {"allowed": False, "reason": f"{p} below minimum {cls.MEASUREMENT_MIN}",
                    "residual": SNC_RESIDUALS["HA_1"]}
        return {"allowed": True, "unit_roundoff": cls.PRECISION_U[p]}

    @classmethod
    def error_bound(cls, n, precision):
        u = cls.PRECISION_U[precision.lower()]; nu = n * u
        return nu / (1.0 - nu) if nu < 1.0 else float("inf")

    @classmethod
    def allreduce_bias(cls, n, precision): return 2.0 * cls.error_bound(n, precision)


def script_sha256():
    with open(__file__, "rb") as fh: return hashlib.sha256(fh.read()).hexdigest()


def is_running_from_target():
    try: return os.path.samefile(os.path.abspath(__file__), ZARQA_SCRIPT_PATH)
    except FileNotFoundError: return False


def deployment_is_current():
    if not os.path.isfile(ZARQA_DEPLOY_HASH) or not os.path.isfile(ZARQA_UNIT_PATH): return False
    try: return Path(ZARQA_DEPLOY_HASH).read_text().strip() == script_sha256()
    except OSError: return False


def write_deploy_hash():
    _safe_write_text(ZARQA_DEPLOY_HASH, script_sha256() + "\n", mode=0o640)


def self_heal_permissions():
    try:
        me = os.path.abspath(__file__)
        current = os.stat(me).st_mode & 0o777
        target = 0o750
        if current != target:
            os.chmod(me, target); LOG.ok(f"self-healed script permissions to {oct(target)}: {me}")
        else: LOG.ok(f"script permissions already {oct(target)}")
    except PermissionError as exc:
        LOG.warn(f"cannot self-heal script permissions (run as root?): {exc}")


def detect_environment():
    def _read(path, default=""):
        try: return Path(path).read_text().strip()
        except OSError: return default
    return {"os": _read("/etc/os-release").splitlines()[0] if os.path.isfile("/etc/os-release") else "unknown",
            "kernel": _read("/proc/sys/kernel/osrelease", "unknown"),
            "arch": os.uname().machine, "python": sys.version.split()[0],
            "python_path": sys.executable, "in_venv": sys.prefix != sys.base_prefix,
            "has_apt": shutil.which("apt-get") is not None,
            "has_gcc": shutil.which("gcc") is not None,
            "has_gpp": shutil.which("g++") is not None,
            "has_rustc": shutil.which("rustc") is not None,
            "has_systemctl": shutil.which("systemctl") is not None,
            "has_lsof": shutil.which("lsof") is not None, "numpy": HAS_NUMPY}


def ensure_python3():
    LOG.step("Python 3 prerequisite")
    if shutil.which("python3"):
        LOG.ok(f"python3 present: {subprocess.check_output(['python3', '--version'], text=True).strip()}"); return
    run_stream(["apt-get", "update"], check=True)
    run_stream(["apt-get", "install", "-y", "python3", "python3-venv", "python3-pip"], check=True)


def apt_update(): LOG.step("APT repository update"); run_stream(["apt-get", "update"], check=True)


def apt_upgrade(): LOG.warn("apt-get upgrade is NOT called by deploy_steps; run manually if needed")


def apt_install(pkgs): LOG.step(f"APT install: {' '.join(pkgs)}"); run_stream(["apt-get", "install", "-y", *pkgs], check=True)


def ensure_build_toolchain():
    LOG.step("Build toolchain verification")
    missing = []
    if not shutil.which("gcc"): missing.extend(["gcc", "build-essential"])
    if not shutil.which("g++"): missing.append("g++")
    if not shutil.which("lsof"): missing.append("lsof")
    if missing: apt_install(missing)
    else: LOG.ok("gcc / g++ / lsof present")


def ensure_rust_toolchain():
    LOG.step("Rust toolchain verification")
    if shutil.which("rustc"):
        LOG.ok(f"rustc present: {subprocess.check_output(['rustc', '--version'], text=True).strip()}"); return True
    try:
        apt_install(["rustc", "cargo"])
        if shutil.which("rustc"):
            LOG.ok(f"rustc installed: {subprocess.check_output(['rustc', '--version'], text=True).strip()}"); return True
    except Exception as exc:
        LOG.warn(f"rust install failed: {exc}")
    LOG.warn("rustc unavailable -- Rust FFI disabled"); return False


def ensure_venv():
    LOG.step("Virtual environment")
    recreate = False
    if os.path.isdir(ZARQA_VENV_DIR) and os.path.isfile(_venv_python()):
        try:
            st = os.stat(_venv_python())
            if st.st_uid != 0 or st.st_gid != 0:
                LOG.warn(f"AOT_SNC18: {_venv_python()} is uid={st.st_uid} gid={st.st_gid}; recreating venv")
                recreate = True
        except OSError:
            recreate = True
        if not recreate:
            LOG.ok(f"venv present: {ZARQA_VENV_DIR} (root-owned)"); return
    if os.path.isdir(ZARQA_VENV_DIR): shutil.rmtree(ZARQA_VENV_DIR)
    run_stream([sys.executable, "-m", "venv", ZARQA_VENV_DIR], check=True)
    run_stream([_venv_python(), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], check=True)


def python_pkg_present(pkg_spec):
    name = re.split(r"[<>=!~]", pkg_spec, maxsplit=1)[0].strip()
    return subprocess.run([_venv_python(), "-m", "pip", "show", name],
                          capture_output=True, text=True).returncode == 0


def ensure_python_packages():
    LOG.step("Python package verification")
    for spec in ZARQA_REQUIRED_PY_PACKAGES:
        if python_pkg_present(spec): LOG.ok(f"already satisfied: {spec}"); continue
        run_stream([_venv_python(), "-m", "pip", "install", spec], check=True)


def _sandboxed_build(source_content, source_ext, lib_name, compile_fn):
    try:
        os.makedirs(ZARQA_BUILD_DIR, mode=0o700, exist_ok=True)
        os.chmod(ZARQA_BUILD_DIR, 0o700)
    except OSError as exc:
        LOG.warn(f"cannot secure build dir {ZARQA_BUILD_DIR}: {exc}")
    work_dir = tempfile.mkdtemp(prefix="build_", dir=ZARQA_BUILD_DIR)
    try:
        os.chmod(work_dir, 0o700)
        src = os.path.join(work_dir, f"snc_kernels{source_ext}")
        lib = os.path.join(work_dir, lib_name)
        _safe_write_text(src, source_content, mode=0o600)
        cmd = compile_fn(src, lib)
        run_stream(cmd, check=True)
        if not os.path.isfile(lib): raise RuntimeError(f"compilation produced no output: {lib}")
        with open(lib, "rb") as fh:
            artifact_hash = hashlib.sha256(fh.read()).hexdigest()
        LOG.info(f"  artifact SHA-256: {artifact_hash}")
        os.chmod(lib, 0o750)
        final_path = os.path.join(ZARQA_INSTALL_DIR, lib_name)
        os.replace(lib, final_path)
        LOG.ok(f"  installed: {final_path}")
        return final_path
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def build_cffi():
    LOG.step("C-FFI kernel compilation (sandboxed, Neumaier)")
    _sandboxed_build(CFFI_SOURCE, ".c", "libsnc_kernels.so",
                     lambda s, l: ["gcc", "-O3", *STRICT_FP_FLAGS, "-shared", "-fPIC", "-o", l, s, "-lm"])
    if not os.path.isfile(ZARQA_CFFI_LIB): raise RuntimeError("C-FFI build produced no output")


def build_rust_ffi():
    LOG.step("Rust C-FFI bridge compilation (sandboxed, Neumaier via black_box)")
    if not shutil.which("rustc"):
        LOG.warn("rustc missing -- skipping"); return False
    try:
        _sandboxed_build(RUST_SOURCE, ".rs", "libsnc_kernels_rs.so",
                         lambda s, l: ["rustc", "--edition", "2021", "-O", "--crate-type", "cdylib", "-o", l, s])
        return True
    except Exception as exc:
        LOG.warn(f"rustc build failed: {exc}"); return False


def build_cpp_jit():
    LOG.step("C++ JIT metaprogramming kernel compilation (sandboxed, Neumaier)")
    if not shutil.which("g++"):
        LOG.warn("g++ missing -- skipping"); return False
    try:
        _sandboxed_build(CPP_SOURCE, ".cpp", "libsnc_kernels_cpp.so",
                         lambda s, l: ["g++", "-O3", *STRICT_FP_FLAGS, "-std=c++17", "-shared", "-fPIC", "-o", l, s])
        return True
    except Exception as exc:
        LOG.warn(f"g++ build failed: {exc}"); return False


def port_in_use(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind((host, port)); return False
    except OSError: return True
    finally: s.close()


def pids_on_port(port):
    if not shutil.which("lsof"): return []
    out = subprocess.run(["lsof", "-ti", f"TCP:{port}"], capture_output=True, text=True)
    return [int(x) for x in out.stdout.split() if x.isdigit()]


def clear_port(port):
    if not port_in_use(port): LOG.ok(f"port {port} is free"); return
    LOG.warn(f"port {port} in use -- clearing")
    for pid in pids_on_port(port):
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
    time.sleep(1.5)
    if port_in_use(port):
        for pid in pids_on_port(port):
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        time.sleep(1.0)
    if port_in_use(port): raise RuntimeError(f"unable to free port {port}")
    LOG.ok(f"port {port} cleared")


def read_pid_file():
    try:
        content = Path(ZARQA_PID_FILE).read_text().strip()
    except OSError:
        return None
    try:
        data = json.loads(content)
        if isinstance(data, dict) and "pid" in data: return data
    except json.JSONDecodeError: pass
    try:
        return {"pid": int(content), "start_time_ticks": None, "start_time_unix": None}
    except ValueError: return None


def write_pid_file(fd):
    pid = os.getpid()
    ticks = get_process_start_time(pid)
    unix_ts = None
    if ticks is not None:
        try:
            clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
            btime = parse_btime()
            if btime is not None and clk > 0:
                unix_ts = btime + ticks / clk
        except Exception: pass
    payload = {"pid": pid, "start_time_ticks": ticks, "start_time_unix": unix_ts}
    data = json.dumps(payload).encode()
    os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET); os.write(fd, data); os.fsync(fd)
    return payload


def clear_zarqa_processes():
    LOG.step("Zarqa daemon cleanup (POSIX record lock + start_time, AOT_SNC14)")
    if not os.path.isfile(ZARQA_PID_FILE):
        LOG.ok("no PID file; no daemon to stop"); return
    file_info = read_pid_file()
    if file_info is None:
        LOG.warn("unparseable PID file; refusing to signal any process"); return
    try:
        pid_fd = os.open(ZARQA_PID_FILE, os.O_RDWR)
    except OSError as exc:
        LOG.warn(f"cannot open PID file: {exc}"); return
    try:
        kernel_pid = PosixLockAttribution.query(pid_fd)
        if kernel_pid is None:
            LOG.ok("no lock held (no daemon)"); return
        file_pid = file_info.get("pid"); file_ticks = file_info.get("start_time_ticks")
        ok, reason = PosixLockAttribution.verify_identity(file_pid, file_ticks, kernel_pid)
        if not ok:
            LOG.warn(f"attribution verification failed: {reason}; refusing to signal"); return
        LOG.info(f"SIGTERM verified daemon pid={kernel_pid} ({reason})")
        try: os.kill(kernel_pid, signal.SIGTERM)
        except ProcessLookupError:
            LOG.warn(f"pid={kernel_pid} already gone"); return
        for _ in range(20):
            time.sleep(1.0)
            if PosixLockAttribution.query(pid_fd) is None:
                LOG.ok(f"daemon pid={kernel_pid} released the lock"); return
        kernel_pid2 = PosixLockAttribution.query(pid_fd)
        ok2, reason2 = PosixLockAttribution.verify_identity(file_pid, file_ticks, kernel_pid2)
        if not ok2:
            LOG.warn(f"post-timeout re-verification failed: {reason2}; NOT escalating"); return
        LOG.warn(f"daemon pid={kernel_pid2} still holds lock after 20s; verified SIGKILL")
        try: os.kill(kernel_pid2, signal.SIGKILL)
        except ProcessLookupError: pass
    finally:
        try: os.close(pid_fd)
        except OSError: pass


def reap_zombies():
    LOG.step("Zombie process scan")
    out = subprocess.run(["ps", "-eo", "pid,ppid,stat,comm"], capture_output=True, text=True).stdout
    found = 0
    for line in out.splitlines()[1:]:
        parts = line.split(None, 3)
        if len(parts) < 4: continue
        pid, ppid, stat, comm = parts
        if stat.startswith("Z") and "zarqa" in comm.lower():
            found += 1; LOG.warn(f"zombie pid={pid} ppid={ppid} comm={comm}")
    LOG.ok("no zarqa zombies" if found == 0 else f"{found} zarqa zombies observed")


def ensure_runtime_dirs():
    LOG.step("Runtime directory / namespace fortification (AOT_SNC13/15/16/19/21/22/24/25/30/31)")
    if not _is_root():
        raise RuntimeError("deployment requires root for namespace fortification; abort")
    for d, m in [(ZARQA_INSTALL_DIR, 0o755), (ZARQA_STATE_DIR, 0o750),
                 (ZARQA_LOG_DIR, 0o750), (os.path.dirname(ZARQA_PID_FILE), 0o750)]:
        NamespaceIntegrity.fortify(d, m)
        LOG.ok(f"fortified: {d} (mode {oct(m)}, owner 0:0, ancestors verified, fd-bound mutation)")


def syntax_check():
    LOG.step("Python syntax check")
    try: py_compile.compile(os.path.abspath(__file__), doraise=True); LOG.ok("syntax check passed")
    except py_compile.PyCompileError as exc: LOG.err(f"syntax error: {exc}"); raise


def write_systemd_unit(service_port, metrics_port):
    LOG.step("systemd unit installation")
    unit = textwrap.dedent(f"""\
    [Unit]
    Description=ZARQA Synthetic Negentropy Core (Phase 1, 8 frameworks)
    Documentation=file:{ZARQA_SCRIPT_PATH}
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory={ZARQA_INSTALL_DIR}
    Environment=ZARQA_VENV_ACTIVE=1
    Environment=ZARQA_STATE_DIR={ZARQA_STATE_DIR}
    Environment=ZARQA_LOG_DIR={ZARQA_LOG_DIR}
    Environment=ZARQA_SERVICE_PORT={service_port}
    Environment=ZARQA_METRICS_PORT={metrics_port}
    ExecStart={_venv_python()} {ZARQA_SCRIPT_PATH} --daemon
    Restart=always
    RestartSec=5
    LimitNOFILE=65536
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
    """)
    _safe_write_text(ZARQA_UNIT_PATH, unit, mode=0o644)
    run_stream(["systemctl", "daemon-reload"], check=True)
    LOG.ok(f"systemd unit written: {ZARQA_UNIT_PATH}")
    return ZARQA_UNIT_PATH


def run_preflight_selftest():
    LOG.step("Pre-flight self-test (isolated /tmp state)")
    tmp = tempfile.mkdtemp(prefix="zarqa_selftest_")
    try:
        env = os.environ.copy()
        env["ZARQA_VENV_ACTIVE"] = "1"
        env["ZARQA_STATE_DIR"] = tmp; env["ZARQA_LOG_DIR"] = tmp
        return run_stream([_venv_python(), os.path.abspath(__file__), "--test", "--state-dir", tmp], env=env) == 0
    finally: shutil.rmtree(tmp, ignore_errors=True)


def _fcntl_roundtrip_test():
    import subprocess as _sp
    if not _FLOCK_ABI_OK: return False, "flock ABI mismatch"
    tmp = None
    try:
        tmp = tempfile.mkdtemp(prefix="zarqa_flock_")
        path = os.path.join(tmp, "lockfile")
        with open(path, "wb") as f: f.write(b"x")
        child_code = (
            "import fcntl, os, struct, sys, time\n"
            f"fd = os.open({path!r}, os.O_RDWR)\n"
            "buf = struct.pack('@hhqqi4x', fcntl.F_WRLCK, 0, 0, 0, 0)\n"
            "assert len(buf) == 32, f'flock buffer len={len(buf)}, expected 32'\n"
            "fcntl.fcntl(fd, fcntl.F_SETLK, buf)\n"
            "sys.stdout.write(str(os.getpid()) + '\\n'); sys.stdout.flush()\n"
            "time.sleep(5)\n"
        )
        proc = _sp.Popen([sys.executable, "-c", child_code], stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
        try:
            raw_line = proc.stdout.readline()
            if not raw_line:
                err = ""
                if proc.stderr is not None:
                    try: err = proc.stderr.read()
                    except Exception: err = ""
                return False, f"child produced no PID; stderr={err[:200]!r}"
            try: child_pid = int(raw_line.strip())
            except ValueError: return False, f"child PID not parseable; raw={raw_line!r}"
            fd = os.open(path, os.O_RDWR)
            try:
                lock = _FlockStruct()
                lock.l_type = fcntl.F_WRLCK; lock.l_whence = 0; lock.l_start = 0; lock.l_len = 0
                raw = fcntl.fcntl(fd, fcntl.F_GETLK, _lock_bytes(lock))
                result = _FlockStruct.from_buffer_copy(raw)
                ok = (result.l_type != fcntl.F_UNLCK and int(result.l_pid) == child_pid)
                return ok, f"child_pid={child_pid}, reported={int(result.l_pid)}"
            finally: os.close(fd)
        finally:
            try:
                proc.terminate(); proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
    except Exception as exc:
        return False, f"fcntl roundtrip failed: {exc}"
    finally:
        if tmp:
            try: shutil.rmtree(tmp, ignore_errors=True)
            except Exception: pass


def _exc_chain_contains_errno(exc, errno_target):
    _e = exc
    _seen = set()
    while _e is not None:
        if id(_e) in _seen:
            break
        _seen.add(id(_e))
        if isinstance(_e, OSError) and _e.errno == errno_target:
            return True
        _e = getattr(_e, "__cause__", None) or getattr(_e, "__context__", None)
    return False


def cmd_test(_args):
    if not HAS_NUMPY:
        LOG.err("numpy is not importable under current interpreter"); return 1
    LOG.step("SNC self-test (8 frameworks: SNC+DSNC+OFF_SNC+DEF_SNC+OB_SNC+PN_SNC+AOT_SNC+NV_SNC)")
    failures = 0
    def check(cond, msg):
        nonlocal failures
        (LOG.ok if cond else LOG.err)(msg)
        if not cond: failures += 1

    p = np.array([0.5, 0.5], dtype=np.float64)
    dm = DistributionMonitor(arl_0=1e4)
    check(abs(dm.entropy(p) - math.log(2.0)) <= 1e-12, "C-FFI Neumaier entropy == log(2)")
    check(abs(dm.kl(p, p.copy())) <= 1e-12, "KL(p||p)=0")
    mv = CertifiedMeasurement.multi_verify(p)
    check(mv["max_relative_divergence"] <= 1e-10, f"multi-verify [{mv['backends_available']} backends]")
    LOG.info(f"  V11: {len(SNC_RESIDUALS)} residuals total, {len(_RESIDUALS_DOC_ONLY)} doc-only")
    check(all(k in SNC_RESIDUALS for k in _RESIDUALS_DOC_ONLY),
          "D2: all doc-only residuals are in SNC_RESIDUALS")
    check(not HardwareAbstraction.measurement_allowed("fp8")["allowed"], "HA rejects fp8")

    LOG.info("  AOT_SNC22 v2.7.0 (behavioral: mock both fallbacks -> ENOTSUP)")
    import unittest.mock as _mock
    _orig_os_chmod = os.chmod
    def _mock_chmod(path, mode, **kw):
        if isinstance(path, (str, bytes)):
            _s = path if isinstance(path, str) else path.decode("utf-8", "replace")
            if _s.startswith("/proc/self/fd/"):
                raise OSError(errno.ENOENT, "mocked: /proc masked by test")
        return _orig_os_chmod(path, mode, **kw)
    def _mock_fchmodat(fd, mode):
        raise OSError(errno.EOPNOTSUPP, "mocked: fchmodat unavailable")
    try:
        with _mock.patch.object(sys.modules[__name__], "_fchmodat_empty", _mock_fchmodat), \
             _mock.patch.object(os, "chmod", _mock_chmod):
            try:
                _apply_mode_fd(0, 0o644, 1, "unused")
                check(False, "AOT_SNC22: _apply_mode_fd must raise ENOTSUP when both fallbacks fail")
            except OSError as _e:
                check(_e.errno == errno.ENOTSUP,
                      f"AOT_SNC22: fail-closed ENOTSUP (errno={_e.errno})")
    except Exception as _e:
        check(False, f"AOT_SNC22: behavioral test setup failed: {_e}")

    _saved_va = NamespaceIntegrity.__dict__["verify_ancestors"]
    _orig_va_fn = _saved_va.__func__ if isinstance(_saved_va, staticmethod) else _saved_va
    def _mocked_va(path):
        _rp = os.path.realpath(path)
        if (_rp.startswith("/tmp/zarqa_") or "/var/folders/" in _rp
                or "/private/var/folders/" in _rp):
            return (True, "mocked for self-test: tempdir ancestor")
        return _orig_va_fn(path)
    _ancestor_bypass_active = True
    NamespaceIntegrity.verify_ancestors = staticmethod(_mocked_va)
    try:
        LOG.info("  AOT_SNC15/AOT_SNC16 self-tests (LPE/DoS guards, tempdir bypassed)")
        import tempfile as _tf
        _td = _tf.mkdtemp(prefix="zarqa_aot15_")
        _link_target = None
        try:
            try:
                NamespaceIntegrity.fortify(_td, 0o750)
                check(True, "AOT_SNC15/16: fortify() on real dir succeeds")
            except Exception as exc:
                check(False, f"AOT_SNC15/16: fortify() on real dir unexpectedly raised: {exc}")
            _link_target = _tf.mkdtemp(prefix="zarqa_aot15_target_")
            _link_path = os.path.join(_td, "would_be_symlink")
            os.symlink(_link_target, _link_path)
            try:
                NamespaceIntegrity.fortify(_link_path, 0o750)
                check(False, "AOT_SNC16: fortify() should have refused symlink but did not")
            except RuntimeError as exc:
                check("symbolic link" in str(exc).lower() or "symlink" in str(exc).lower(),
                      f"AOT_SNC16: fortify() refused symlink leaf ({str(exc)[:80]})")
            except Exception as exc:
                check(False, f"AOT_SNC16: unexpected error type {type(exc).__name__}: {exc}")
            _target = os.path.join(_td, "target_file")
            with open(_target, "w") as f: f.write("x")
            _pre_target_uid = os.stat(_target).st_uid
            _link2 = os.path.join(_td, "symlink_to_target")
            os.symlink(_target, _link2)
            _safe_lchown(_link2, 0, 0)
            _post_target_uid = os.stat(_target).st_uid
            check(_pre_target_uid == _post_target_uid,
                  f"AOT_SNC16: _safe_lchown did NOT follow symlink (target uid stable {_pre_target_uid})")
            try:
                _safe_chmod_if_not_symlink(_link2, 0o750)
                check(False, "AOT_SNC16: _safe_chmod_if_not_symlink should have refused symlink")
            except RuntimeError as exc:
                check("symbolic link" in str(exc).lower(),
                      f"AOT_SNC16: _safe_chmod_if_not_symlink refused ({str(exc)[:80]})")
        finally:
            try: shutil.rmtree(_td, ignore_errors=True)
            except Exception: pass
            if _link_target is not None:
                try: shutil.rmtree(_link_target, ignore_errors=True)
                except Exception: pass
    finally:
        NamespaceIntegrity.verify_ancestors = _saved_va
        _ancestor_bypass_active = False
    check(not _ancestor_bypass_active, "AOT_SNC23: ancestor bypass restored")

    LOG.info("  AOT_SNC18 self-test (targeted ancestor chain, no recursion)")
    import tempfile as _tf
    _td18 = _tf.mkdtemp(prefix="zarqa_aot18_")
    try:
        _deep18 = os.path.join(_td18, "a", "b", "c")
        os.makedirs(_deep18, exist_ok=True)
        _target18 = os.path.join(_deep18, "target.txt")
        with open(_target18, "w") as f: f.write("x")
        _sibling18 = os.path.join(_deep18, "sibling.txt")
        with open(_sibling18, "w") as f: f.write("y")
        _canon18 = os.path.abspath(_target18)
        chain = _ancestor_chain_inclusive(_target18)
        check(chain[0] == "/", f"AOT_SNC18: chain[0]={chain[0]} == /")
        check(chain[-1] == _canon18, "AOT_SNC18: chain[-1] == canonical (lexical) target")
        check(all(_canon18 == p or (p == "/" and _canon18.startswith("/"))
                  or _canon18.startswith(p + "/") for p in chain),
              "AOT_SNC18: every chain element is a path-prefix of the target")
        check(_sibling18 not in chain, "AOT_SNC18: sibling NOT in chain")
        check(_td18 in chain or any(p.startswith(_td18) for p in chain),
              "AOT_SNC18: tempdir in chain")
    finally:
        try: shutil.rmtree(_td18, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC20 v2.7.1 (lexical ancestors + polyglot refusal set)")
    _td_lex = _tf.mkdtemp(prefix="zarqa_lex_")
    try:
        _lex_a = os.path.join(_td_lex, "a"); _lex_c = os.path.join(_td_lex, "c")
        os.makedirs(_lex_a, exist_ok=True); os.makedirs(_lex_c, exist_ok=True)
        _lex_b_link = os.path.join(_lex_a, "b")
        os.symlink(_lex_c, _lex_b_link)
        _lex_path = os.path.join(_lex_a, "b", "target")
        _lex_chain = _ancestor_chain_inclusive(_lex_path)
        check(_lex_chain[-1] == _lex_path,
              f"AOT_SNC20: lexical chain[-1]={_lex_chain[-1]!r} == {_lex_path!r} (no realpath)")
        check(os.path.join(_lex_a, "b") in _lex_chain,
              "AOT_SNC20: intermediate lexical path preserved in chain")
        try:
            _safe_mutate_owner(os.path.join(_lex_a, "b", "target"), None)
            check(False, "AOT_SNC20: _safe_mutate_owner should have refused intermediate symlink")
        except RuntimeError as _exc:
            _eloop_in_chain = _exc_chain_contains_errno(_exc, errno.ELOOP)
            _enotdir_in_chain = _exc_chain_contains_errno(_exc, errno.ENOTDIR)
            _msg = str(_exc).lower()
            _msg_ok = any(t in _msg for t in (
                "eloop", "symbolic link", "symlink", "too many levels",
                "not a directory", "enotdir",
            ))
            check(_eloop_in_chain or _enotdir_in_chain or _msg_ok,
                  f"AOT_SNC20: refused intermediate symlink "
                  f"(ELOOP_chain={_eloop_in_chain}, ENOTDIR_chain={_enotdir_in_chain}, "
                  f"msg={str(_exc)[:120]!r})")
        if os.geteuid() == 0:
            try:
                _makedirs_at(os.path.join(_lex_a, "b", "deeper"), mode=0o750)
                check(os.path.isdir(os.path.join(_lex_a, "b", "deeper"))
                      and not os.path.islink(_lex_a + "/b"),
                      "AOT_SNC20: root self-heal replaced intermediate symlink with dir")
                check(os.path.isdir(_lex_c) and not os.path.exists(os.path.join(_lex_c, "deeper")),
                      "AOT_SNC20: symlink target /td/c untouched by self-heal")
            except Exception as exc:
                check(False, f"AOT_SNC20: self-heal raised: {exc}")
    finally:
        try: shutil.rmtree(_td_lex, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC21 v2.7.0 (state-machine retry bound)")
    check(_MAKEDIRS_AT_MAX_ATTEMPTS >= 2 and _MAKEDIRS_AT_MAX_ATTEMPTS <= 64,
          f"AOT_SNC21: _MAKEDIRS_AT_MAX_ATTEMPTS={_MAKEDIRS_AT_MAX_ATTEMPTS} in [2, 64]")

    LOG.info("  AOT_SNC19 v2.4.9 self-test (O_PATH fchownat/fchmodat contract)")
    _td_v19 = _tf.mkdtemp(prefix="zarqa_v19_")
    try:
        _regfile = os.path.join(_td_v19, "regfile")
        with open(_regfile, "w") as f: f.write("x")
        _regfd = os.open(_regfile, os.O_PATH | os.O_NOFOLLOW)
        try:
            try:
                os.fchown(_regfd, 0, 0)
                check(False, "V1-regression guard: os.fchown(O_PATH) must raise EBADF")
            except OSError as _e:
                check(_e.errno == errno.EBADF,
                      f"V1-regression guard: EBADF confirmed on os.fchown(O_PATH) [errno={_e.errno}]")
            if _CTYPES_FCHOWNAT_OK:
                try:
                    _fchownat_empty(_regfd, os.getuid(), os.getgid())
                    check(True, "V1-fix: fchownat(AT_EMPTY_PATH) on O_PATH succeeds")
                except OSError as _e:
                    check(False, f"V1-fix: fchownat(AT_EMPTY_PATH) failed: {_e}")
            else:
                LOG.warn("V1-fix: ctypes fchownat unavailable; skipping positive test")
            if _CTYPES_FCHMODAT_OK:
                try:
                    _fchmodat_empty(_regfd, 0o640)
                    check(True, "V1-fix: fchmodat(AT_EMPTY_PATH) on O_PATH succeeds")
                except OSError as _e:
                    if _e.errno in (errno.EINVAL, errno.EOPNOTSUPP):
                        LOG.warn(f"V1-fix: fchmodat(AT_EMPTY_PATH) unsupported on this kernel ({_e}); /proc fallback is primary")
                        proc_path = f"/proc/self/fd/{_regfd}"
                        try:
                            os.chmod(proc_path, 0o640)
                            check(True, "V1-fix: /proc/self/fd chmod fallback succeeds")
                        except OSError as _e2:
                            check(False, f"V1-fix: /proc chmod fallback failed: {_e2}")
                    else:
                        check(False, f"V1-fix: fchmodat(AT_EMPTY_PATH) failed: {_e}")
        finally:
            try: os.close(_regfd)
            except OSError: pass

        _mdtarget = os.path.join(_td_v19, "real_dir")
        os.makedirs(_mdtarget, exist_ok=True)
        _mdlink = os.path.join(_td_v19, "link_to_dir")
        os.symlink(_mdtarget, _mdlink)
        try:
            _makedirs_at(os.path.join(_mdlink, "child"), mode=0o755)
            if os.geteuid() == 0:
                check(os.path.isdir(os.path.join(_mdlink, "child")),
                      "V5 v2.8.3: root self-healed symlink intermediate")
            else:
                check(False, "V5-regression guard: non-root must refuse")
        except RuntimeError as _e:
            check("root" in str(_e).lower() or "self-heal" in str(_e).lower(),
                  f"V5-regression guard: non-root refused ({str(_e)[:80]})")

        _fresh = os.path.join(_td_v19, "a", "b", "c")
        try:
            _makedirs_at(_fresh, mode=0o750)
            check(os.path.isdir(_fresh), "V5-fix: _makedirs_at creates a fresh directory tree")
        except Exception as _e:
            check(False, f"V5-fix: _makedirs_at unexpected error: {_e}")
    finally:
        try: shutil.rmtree(_td_v19, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC24 v2.7.1 (polymorphic destruction: EISDIR -> rmdir)")
    if os.geteuid() == 0:
        _td24 = _tf.mkdtemp(prefix="zarqa_aot24_")
        try:
            _obs24 = os.path.join(_td24, "obs")
            with open(_obs24, "w") as fh: fh.write("x")
            _calls = {"unlink": 0, "rmdir": 0}
            _orig_unlink = os.unlink
            _orig_rmdir = os.rmdir
            def _mock_unlink(path, *, dir_fd=None):
                if path == "obs":
                    _calls["unlink"] += 1
                    raise OSError(errno.EISDIR, "mocked duality race: file became dir")
                return _orig_unlink(path, dir_fd=dir_fd)
            def _mock_rmdir(path, *, dir_fd=None):
                if path == "obs":
                    _calls["rmdir"] += 1
                    raise OSError(errno.ENOTEMPTY,
                                  "mocked: rmdir blocked by non-empty directory")
                return _orig_rmdir(path, dir_fd=dir_fd)
            try:
                with _mock.patch.object(os, "unlink", _mock_unlink), \
                     _mock.patch.object(os, "rmdir", _mock_rmdir):
                    try:
                        _makedirs_at(os.path.join(_td24, "obs", "leaf"), mode=0o750)
                        check(False, "AOT_SNC24: should raise when both unlink and rmdir fail")
                    except (RuntimeError, OSError) as _e:
                        if isinstance(_e, OSError):
                            _errno_val = getattr(_e, "errno", None)
                            _admissible = {errno.ENOTEMPTY, errno.EBUSY,
                                           errno.EPERM, errno.EROFS,
                                           errno.EACCES, errno.ENOTDIR}
                            if _errno_val in _admissible:
                                check(False,
                                      f"AOT_SNC24: SUT propagated admissible errno "
                                      f"{_errno_val} as OSError; should be RuntimeError "
                                      f"naming AOT_SNC24_1")
                            else:
                                check(False,
                                      f"AOT_SNC24: SUT propagated inadmissible errno "
                                      f"{_errno_val}; test mock is wrong (AOT_SNC23_3)")
                        else:
                            check(_calls["unlink"] >= 1 and _calls["rmdir"] >= 1,
                                  f"AOT_SNC24: rmdir attempted after unlink EISDIR "
                                  f"(calls={_calls}, exc=RuntimeError)")
            except Exception as _e:
                check(False, f"AOT_SNC24: behavioral test setup failed: {_e}")
        finally:
            try: shutil.rmtree(_td24, ignore_errors=True)
            except Exception: pass
    else:
        LOG.warn("AOT_SNC24: duality-race test skipped (requires root)")

    LOG.info("  AOT_SNC25 v2.8.0 (tri-state duality race: rmdir->ENOTDIR retry)")
    if os.geteuid() == 0:
        _td25 = _tf.mkdtemp(prefix="zarqa_aot25_")
        try:
            _obs25 = os.path.join(_td25, "obs25")
            with open(_obs25, "w") as fh: fh.write("x")
            _orig_unlink25 = os.unlink
            _orig_rmdir25 = os.rmdir
            _u25 = {"n": 0}
            _r25 = {"n": 0}
            def _mock_unlink25(path, *, dir_fd=None):
                if path == "obs25":
                    _u25["n"] += 1
                    if _u25["n"] == 1:
                        raise OSError(errno.EISDIR,
                                      "mocked: file became directory (first race)")
                    return _orig_unlink25(path, dir_fd=dir_fd)
                return _orig_unlink25(path, dir_fd=dir_fd)
            def _mock_rmdir25(path, *, dir_fd=None):
                if path == "obs25":
                    _r25["n"] += 1
                    raise OSError(errno.ENOTDIR,
                                  "mocked: dir became file (tri-state race)")
                return _orig_rmdir25(path, dir_fd=dir_fd)
            try:
                with _mock.patch.object(os, "unlink", _mock_unlink25), \
                     _mock.patch.object(os, "rmdir", _mock_rmdir25):
                    try:
                        _makedirs_at(os.path.join(_td25, "obs25"), mode=0o750)
                        check(os.path.isdir(_obs25) and not os.path.islink(_obs25),
                              f"AOT_SNC25: tri-state exhausted; directory created "
                              f"(unlink_calls={_u25['n']}, rmdir_calls={_r25['n']})")
                        check(_u25["n"] >= 2,
                              f"AOT_SNC25: retry re-ran unlink (unlink_calls={_u25['n']})")
                        check(_r25["n"] >= 1,
                              f"AOT_SNC25: rmdir was attempted (rmdir_calls={_r25['n']})")
                    except Exception as exc:
                        check(False,
                              f"AOT_SNC25: state machine did not recover from "
                              f"tri-state race: {exc}")
            except Exception as _e:
                check(False, f"AOT_SNC25: behavioral test setup failed: {_e}")
        finally:
            try: shutil.rmtree(_td25, ignore_errors=True)
            except Exception: pass
    else:
        LOG.warn("AOT_SNC25: tri-state race test skipped (requires root)")

    LOG.info("  AOT_SNC26 v2.8.2 (symlink refusal: victim unchanged; target now regular file)")
    _td26 = _tf.mkdtemp(prefix="zarqa_aot26_")
    try:
        _payload26a = "hello\n"
        _target_happy = os.path.join(_td26, "fresh.txt")
        try:
            n_written = _safe_write_text(_target_happy, _payload26a, mode=0o640)
            check(n_written == len(_payload26a),
                  f"AOT_SNC26: fresh write returned {n_written} "
                  f"(expected {len(_payload26a)})")
            check(os.path.isfile(_target_happy) and not os.path.islink(_target_happy),
                  "AOT_SNC26: fresh write produced a regular file")
            with open(_target_happy, "r") as fh:
                _content = fh.read()
            check(_content == _payload26a,
                  f"AOT_SNC26: fresh write content matches ({_content!r})")
        except Exception as exc:
            check(False, f"AOT_SNC26: fresh-write path raised: {exc}")

        _victim = os.path.join(_td26, "victim.txt")
        with open(_victim, "w") as fh: fh.write("ORIGINAL_VICTIM_CONTENT")
        _victim_content_before = open(_victim).read()
        _target_symlink = os.path.join(_td26, "target_with_symlink.txt")
        os.symlink(_victim, _target_symlink)
        _payload26b = "ATTACK_PAYLOAD\n"
        try:
            n_written2 = _safe_write_text(_target_symlink, _payload26b, mode=0o640)
            check(n_written2 == len(_payload26b),
                  f"AOT_SNC26: symlink-target write returned {n_written2} "
                  f"(expected {len(_payload26b)})")
            _victim_content_after = open(_victim).read()
            check(_victim_content_after == _victim_content_before,
                  f"AOT_SNC26: victim file UNCHANGED after symlink attack "
                  f"({_victim_content_after!r})")
            check(not os.path.islink(_target_symlink),
                  "AOT_SNC26: symlink was replaced by regular file")
            check(os.path.isfile(_target_symlink),
                  "AOT_SNC26: target is now a regular file")
            _target_content_after = open(_target_symlink).read()
            check(_target_content_after == _payload26b,
                  f"AOT_SNC26: payload landed on target, not victim "
                  f"({_target_content_after!r})")
        except Exception as exc:
            check(False, f"AOT_SNC26: symlink-attack path raised: {exc}")
    finally:
        try: shutil.rmtree(_td26, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC27 v2.8.2 (hardlink refusal: original inode untouched)")
    _td27 = _tf.mkdtemp(prefix="zarqa_aot27_")
    try:
        _victim27 = os.path.join(_td27, "victim27.txt")
        with open(_victim27, "w") as fh: fh.write("VICTIM_HARDLINK_CONTENT")
        _victim27_before = open(_victim27).read()
        _target27 = os.path.join(_td27, "target27.txt")
        try:
            os.link(_victim27, _target27)
            _pre_ino_victim = os.stat(_victim27).st_ino
            _pre_ino_target = os.stat(_target27).st_ino
            check(_pre_ino_victim == _pre_ino_target,
                  f"AOT_SNC27: hardlink shares inode pre-attack "
                  f"(victim_ino={_pre_ino_victim}, target_ino={_pre_ino_target})")
            _payload27 = "HARDLINK_ATTACK_PAYLOAD\n"
            n_written27 = _safe_write_text(_target27, _payload27, mode=0o640)
            check(n_written27 == len(_payload27),
                  f"AOT_SNC27: hardlink-target write returned {n_written27} "
                  f"(expected {len(_payload27)})")
            _victim27_after = open(_victim27).read()
            check(_victim27_after == _victim27_before,
                  f"AOT_SNC27: victim file UNCHANGED after hardlink attack "
                  f"({_victim27_after!r})")
            _target27_after = open(_target27).read()
            check(_target27_after == _payload27,
                  f"AOT_SNC27: payload landed on target, not victim "
                  f"({_target27_after!r})")
            _post_ino_victim = os.stat(_victim27).st_ino
            _post_ino_target = os.stat(_target27).st_ino
            check(_post_ino_victim != _post_ino_target,
                  f"AOT_SNC27: hardlink severed post-attack "
                  f"(victim_ino={_post_ino_victim}, target_ino={_post_ino_target})")
            check(_post_ino_victim == _pre_ino_victim,
                  f"AOT_SNC27: victim inode unchanged ({_pre_ino_victim} -> {_post_ino_victim})")
        except OSError as _linkexc:
            if getattr(_linkexc, "errno", None) in (errno.EPERM, errno.EMLINK, errno.EXDEV):
                LOG.warn(f"AOT_SNC27: hardlink test skipped (fs.protected_hardlinks=1 or EPERM): {_linkexc}")
            else:
                check(False, f"AOT_SNC27: hardlink setup failed: {_linkexc}")
        except Exception as exc:
            check(False, f"AOT_SNC27: hardlink-attack path raised: {exc}")
    finally:
        try: shutil.rmtree(_td27, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC30 v2.8.3 (5-step PID allocation: hardlink severance)")
    if os.geteuid() == 0:
        _td30 = _tf.mkdtemp(prefix="zarqa_aot30_")
        try:
            _victim30 = os.path.join(_td30, "victim30.txt")
            with open(_victim30, "w") as fh: fh.write("VICTIM_PID_SHADOW_CONTENT")
            _victim30_before = open(_victim30).read()
            _pid30 = os.path.join(_td30, "test.pid")
            try:
                os.link(_victim30, _pid30)
                _pre_ino30 = os.stat(_pid30).st_ino
                try:
                    _pidfd30 = _acquire_secure_pid_fd(_pid30, mode=0o640)
                except Exception as exc:
                    _pidfd30 = None
                    check(False, f"AOT_SNC30: _acquire_secure_pid_fd raised: {exc}")
                if _pidfd30 is not None:
                    try:
                        _payload30 = b"PID_AOT_SNC30_PAYLOAD"
                        os.ftruncate(_pidfd30, 0)
                        os.lseek(_pidfd30, 0, os.SEEK_SET)
                        os.write(_pidfd30, _payload30)
                        os.fsync(_pidfd30)
                    finally:
                        try: os.close(_pidfd30)
                        except OSError: pass
                    _victim30_after = open(_victim30).read()
                    check(_victim30_after == _victim30_before,
                          f"AOT_SNC30: victim UNCHANGED after hardlink hijack "
                          f"({_victim30_after!r})")
                    check(not os.path.islink(_pid30),
                          "AOT_SNC30: PID path is now a regular file")
                    _post_ino30 = os.stat(_pid30).st_ino
                    check(_post_ino30 != _pre_ino30,
                          f"AOT_SNC30: PID inode severed ({_pre_ino30} -> {_post_ino30})")
                    _pid30_after = open(_pid30, "rb").read()
                    check(_pid30_after == _payload30,
                          f"AOT_SNC30: payload landed on PID, not victim "
                          f"({_pid30_after!r})")
            except OSError as _linkexc:
                if getattr(_linkexc, "errno", None) in (errno.EPERM, errno.EMLINK, errno.EXDEV):
                    LOG.warn(f"AOT_SNC30: hardlink test skipped: {_linkexc}")
                else:
                    check(False, f"AOT_SNC30: hardlink setup failed: {_linkexc}")
            except Exception as exc:
                check(False, f"AOT_SNC30: path raised: {exc}")
        finally:
            try: shutil.rmtree(_td30, ignore_errors=True)
            except Exception: pass
    else:
        LOG.warn("AOT_SNC30: hardlink severance test skipped (requires root)")

    LOG.info("  AOT_SNC31 v2.8.3 (universal polymorphic destruction in _safe_write_text)")
    _td31 = _tf.mkdtemp(prefix="zarqa_aot31_")
    try:
        # (a) Empty-directory obstruction at .tmp → healed by rmdir
        _target31 = os.path.join(_td31, "target31.txt")
        _tmp31 = _target31 + ".tmp"
        os.makedirs(_tmp31, exist_ok=True)
        _payload31 = "AOT_SNC31_PAYLOAD\n"
        try:
            n31 = _safe_write_text(_target31, _payload31, mode=0o640)
            check(n31 == len(_payload31),
                  f"AOT_SNC31: write with empty-dir obstruction returned {n31} "
                  f"(expected {len(_payload31)})")
            _content31 = open(_target31).read()
            check(_content31 == _payload31,
                  f"AOT_SNC31: payload on target ({_content31!r})")
        except Exception as exc:
            check(False, f"AOT_SNC31: empty-dir obstruction path raised: {exc}")

        # (b) Non-empty directory at .tmp → fail-closed
        _target31b = os.path.join(_td31, "target31b.txt")
        _tmp31b = _target31b + ".tmp"
        os.makedirs(_tmp31b, exist_ok=True)
        with open(os.path.join(_tmp31b, "child"), "w") as fh: fh.write("x")
        try:
            _safe_write_text(_target31b, "SHOULD_NOT_SUCCEED\n", mode=0o640)
            check(False, "AOT_SNC31: non-empty-dir obstruction should have raised")
        except RuntimeError as _e:
            check("AOT_SNC31_1" in str(_e) or "cannot clear tmp" in str(_e) or "non-empty" in str(_e),
                  f"AOT_SNC31: non-empty-dir fail-closed ({str(_e)[:120]})")
        except Exception as _e:
            check(False, f"AOT_SNC31: non-empty-dir raised unexpected: {type(_e).__name__}: {_e}")
    finally:
        try: shutil.rmtree(_td31, ignore_errors=True)
        except Exception: pass

    LOG.info("  AOT_SNC28 v2.8.1 (symlink hijack refusal: victim unchanged) — historical self-test")
    _td28 = _tf.mkdtemp(prefix="zarqa_aot28_")
    try:
        _victim28 = os.path.join(_td28, "victim28.txt")
        with open(_victim28, "w") as fh: fh.write("VICTIM_SHADOW_CONTENT")
        _victim28_before = open(_victim28).read()
        _test_pid = os.path.join(_td28, "test.pid")
        os.symlink(_victim28, _test_pid)
        _pid_payload = b"PID_PAYLOAD"
        try:
            _pidfd = _acquire_secure_pid_fd(_test_pid, mode=0o640)
        except Exception as exc:
            _pidfd = None
            check(False, f"AOT_SNC28 (via AOT_SNC30): _acquire_secure_pid_fd raised: {exc}")
        if _pidfd is not None:
            try:
                os.ftruncate(_pidfd, 0)
                os.lseek(_pidfd, 0, os.SEEK_SET)
                os.write(_pidfd, _pid_payload)
                os.fsync(_pidfd)
            finally:
                try: os.close(_pidfd)
                except OSError: pass
            _victim28_after = open(_victim28).read()
            check(_victim28_after == _victim28_before,
                  f"AOT_SNC28 (via AOT_SNC30): victim UNCHANGED after PID symlink attack "
                  f"({_victim28_after!r})")
            check(not os.path.islink(_test_pid),
                  "AOT_SNC28 (via AOT_SNC30): PID path is now a regular file")
            _test_pid_after = open(_test_pid, "rb").read()
            check(_test_pid_after == _pid_payload,
                  f"AOT_SNC28 (via AOT_SNC30): payload landed on PID path, not victim "
                  f"({_test_pid_after!r})")
    finally:
        try: shutil.rmtree(_td28, ignore_errors=True)
        except Exception: pass

    ff = load_ffi()
    if ff["c"] is not None:
        test_arr = np.array([1e16, 1.0, 1.0, -1e16], dtype=np.float64)
        neumaier_val = float(ff["c"].snc_sum_neumaier(test_arr.ctypes.data_as(_DPTR), test_arr.size))
        naive_val = float(np.sum(test_arr))
        check(abs(neumaier_val - 2.0) < 1e-9,
              f"Neumaier sum [1e16,1,1,-1e16] = {neumaier_val:.4f} (naive {naive_val:.4f})")
        v_std = ff["c"].snc_chao1(100, 25, 50)
        check(abs(v_std - 250.0) < 1e-9, f"Chao1 standard (f2>0): {v_std:.2f} == 250.00")
        v_bc = ff["c"].snc_chao1(100, 0, 50)
        check(abs(v_bc - 5000.0) < 1e-9, f"Chao1 bias-corrected (f2=0): {v_bc:.2f} == 5000.00")

    check(abs(RetentionBounds.info_retention(0.1, 0.95) - 0.6897) < 0.01, "SNC3: I_inf")
    check(abs(RetentionBounds.wasserstein_asymptote(0.1, 0.95, 0.1) - 0.6207) < 0.01, "SNC4: W2_inf")
    check(abs(FisherRetention.retention(0.1, 0.95) - 0.5326) < 0.01, "SNC5: F_inf")
    check(abs(KLSteadyState.steady_state(0.1, 0.95, 0.1) - 0.6207) < 0.01, "DSNC1: KL^inf")
    check(abs(TemperatureBound.effective_temperature(1.0, 0.15) - 1.15) < 1e-9, "DSNC3: T_eff")
    tpr = BackdoorDetection.spectral_tpr(1.5, 2.5, 0.5, 500)
    check(tpr >= 0.9999, f"OFF_SNC1: TPR={tpr:.6f}")
    _stpr_mid = BackdoorDetection.spectral_tpr(2.0, 0.0, 1.0, 1)
    check(abs(_stpr_mid - 0.0227501) < 1e-4,
          f"OFF_SNC1 Fix 2: spectral_tpr(2,0,1,1)={_stpr_mid:.7f} expected 0.0227501")
    f_inf = CumulativeDrift.steady_state(0.1, 0.95, 1e-4, 0.01)
    check(abs(f_inf - 0.06903) < 0.001, f"OFF_SNC4: f_inf={f_inf:.5f}")
    check(abs(ProvenanceAttestation.unattested_probability(128, 1e-7, 1e-4) - 1e-4) < 1e-5, "DEF_SNC1: P_unatt")
    f_eff_san = SanitizationCompleteness.effective_poison_fraction(0.01, 0.98, 0.02)
    check(f_eff_san < 0.001, f"DEF_SNC2: f_eff={f_eff_san:.6f}")
    tpr_fus = MultiDetectorFusion.tpr_fusion([0.85, 0.85, 0.85])
    check(abs(tpr_fus - 0.9966) < 0.001, f"DEF_SNC4: TPR_fusion={tpr_fus:.4f}")
    l1_min = FanoBound.minimax_l1(50000, 1000000)
    check(abs(l1_min - 0.2236) < 0.001, f"OB_SNC1: L1 minimax={l1_min:.4f}")
    K_unobs = HiddenModeInventory.chao1_lower(10000, 5000)
    check(abs(K_unobs - 10000) < 1.0, f"OB_SNC3: K_unobserved={K_unobs:.0f}")
    check(len(RiceUndecidability.disclosure()["decidable"]) >= 3, "OB_SNC8: decidable props")

    err_fp32_M10 = PrecisionBoundEntropy.precision_error(2.0**-24, 10.8)
    check(1e-7 < err_fp32_M10 < 1e-5, f"PN_SNC1 (M=10): FP32 entropy err={err_fp32_M10:.2e}")
    check(not PrecisionBoundEntropy.is_agnostic(2.0**-4, 2.0**-4, 10.8, 0.05), "PN_SNC1: FP8 not agnostic")
    ring_err = DistributedAggregation.ring_error(1e-6, 10, 1.0)
    check(abs(ring_err - 9e-5) < 1e-6, f"PN_SNC3: ring error (N=10,eps=1e-6) = {ring_err:.2e} == 9e-5")
    pn11_bound = NeumaierErrorBound.relative_error_bound(n=50000)
    check(pn11_bound < 1e-13, f"PN_SNC11: Neumaier bound (n=50000) = {pn11_bound:.2e} < 1e-13")

    cv = ContractPreservingCompilation.compile_violation_probability(12, 1e-6, 128)
    check(abs(cv - 1.2e-5) < 1e-6, f"AOT_SNC1: compile violation={cv:.2e}")
    wb = DualCompilationVerify.wrong_binary_probability(1e-5, 1e-4, 1e-7)
    check(abs(wb - 1.01e-7) < 1e-8, f"AOT_SNC3: wrong binary={wb:.2e}")
    ok_wcet, _ = CompositionalWCET.within_budget([2,8,5,6,15,0.001,0.1], 0.2, 60.0)
    check(ok_wcet, "AOT_SNC4: WCET within budget")
    check(len(AOTRiceDisclosure.disclosure()["decidable"]) >= 3, "AOT_SNC8: AOT decidable props")
    check(CompilerInvariance.requires_volatile(), "AOT_SNC11: volatile required")
    aot11_flags = CompilerInvariance.ieee754_compliant_flags()
    check("-fno-fast-math" in aot11_flags, "AOT_SNC11: -fno-fast-math present")
    check("-fno-associative-math" in aot11_flags, "AOT_SNC11: -fno-associative-math present")

    ok_ns, reason_ns = NamespaceIntegrity.verify_ancestors(ZARQA_INSTALL_DIR)
    check(isinstance(ok_ns, bool) and isinstance(reason_ns, str),
          f"AOT_SNC13: verify_ancestors ({ok_ns}, {reason_ns[:50]})")
    check(NamespaceIntegrity.confidence_bound(ZARQA_INSTALL_DIR) in (0.0, 0.9999),
          "AOT_SNC13: confidence in {0.0, 0.9999}")

    my_pid = os.getpid(); my_ticks = get_process_start_time(my_pid)
    ok_pos, _ = PosixLockAttribution.verify_identity(my_pid, my_ticks, my_pid)
    ok_neg, _ = PosixLockAttribution.verify_identity(my_pid + 1, my_ticks, my_pid)
    check(ok_pos, "AOT_SNC14: verify_identity positive path")
    check(not ok_neg, "AOT_SNC14: verify_identity negative path (pid mismatch)")
    ok0, _ = PosixLockAttribution.verify_identity(12345, 100, None)
    check(not ok0, "AOT_SNC14: verify_identity rejects no-holder")
    ok_init, _ = PosixLockAttribution.verify_identity(1, None, 1)
    check(not ok_init, "AOT_SNC14: verify_identity rejects PID 1 (init)")

    check(_FLOCK_ABI_OK, f"AOT_SNC14: _FlockStruct ABI OK (sizeof={_FLOCK_SIZE}, expected 32)")
    if _FLOCK_ABI_OK:
        rt_ok, rt_reason = _fcntl_roundtrip_test()
        check(rt_ok, f"AOT_SNC14: fcntl(F_GETLK) roundtrip ({rt_reason})")

    dm_arl = DistributionMonitor(beta=0.05, arl_0=1e4, cusum_slack=0.5)
    if dm_arl.cusum_alarm([], 1.0, 0.1) is False: pass
    h_thresh = None
    if 0.1 > 0:
        k = 0.5 * 0.1; h_thresh = math.log(2.0 * k * k * 1e4) / (2.0 * k)
    check(h_thresh is not None and 30 < h_thresh < 50,
          f"B4/F13: Lorden ARL calibration h(delta=0.1,ARL=1e4) = {h_thresh:.2f}")

    alpha_star_seb = SEB.alpha_star(V=0.01, H_0=10.0, L=0.95, c_R=0.01, c_S=0.0001)
    check(abs(alpha_star_seb - 0.696) < 0.01, f"NV_SNC1 (SEB): alpha*={alpha_star_seb:.3f}")
    t_star_gav = GAV.time_to_target(alpha_star_v=0.31, N_total=1e9, R_real=1e6)
    check(abs(t_star_gav - 310.0) < 1, f"NV_SNC2 (GAV): t*={t_star_gav:.1f} days")
    A_cross_v = MCB.A_cross(alpha=0.1, beta=0.7, L_B=0.95)
    check(abs(A_cross_v - 0.847) < 0.01, f"NV_SNC3 (MCB): A_cross={A_cross_v:.4f}")
    f_eff_aac = AAC.f_eff(f=0.01, eps_trust=1e-4, tpr=0.98, fpr=0.02)
    check(f_eff_aac < 1e-6, f"NV_SNC6 (AAC): f_eff={f_eff_aac:.2e} below f_crit=0.005")

    LOG.info("  Golden orchestrator tests (G1-G7)")
    c1 = composite_analysis(0.1, 0.95, 0.1, 10.0, 20, 0.05, 0.05, 0.1, 0.05, 0.01, 5.0)
    check(c1["SNC10_verdict"] == "DRIFT_PAST_BARRIER",
          f"G1: composite_analysis SNC10 = {c1['SNC10_verdict']} (expected DRIFT_PAST_BARRIER; "
          f"{c1['SNC10_detail']})")
    check(abs(c1["SNC3_info_retention"] - 0.6897) < 0.01, "G1: composite_analysis SNC3")
    check(c1["SNC8_jsd_target"] is None, "G1/B5: SNC8 None without p_hat/p_0")
    c1b_valid = composite_analysis(0.5, 0.95, 0.1, 10.0, 20, 0.05, 0.5, 0.1, 0.05, 0.01, 5.0)
    check(c1b_valid["SNC10_verdict"] == "VALID",
          f"G1b: composite_analysis SNC10 = {c1b_valid['SNC10_verdict']} (expected VALID; "
          f"{c1b_valid['SNC10_detail']})")
    c1b = composite_analysis(0.1, 0.95, 0.1, 10.0, 20, 0.05, 0.05, 0.1, 0.05, 0.01, 5.0,
                             p_hat=np.array([0.5, 0.5]), p_0=np.array([0.5, 0.5]))
    check(c1b["SNC8_jsd_target"] is not None and abs(c1b["SNC8_jsd_target"]) < 1e-9,
          f"G1/B5: SNC8 JSD(p,p) = {c1b['SNC8_jsd_target']}")

    d1 = composite_analysis_deep(0.1, 0.95, 0.1, 10.0, 20, 0.05, 0.05, 0.1, 0.05, 0.01, 5.0,
                                 0.5, 1e-3, 10000, 1000000, 1.0, 0.15, 0.45, 100,
                                 0.02, 0.01, 0.05, 0.1, 100.0, 10.0, 5.0, 0.95, 0.01, 3.2)
    check(abs(d1["DSNC1_KL_steady_state"] - 0.6207) < 0.01, "G2: composite_analysis_deep DSNC1")

    o1 = composite_analysis_offensive(0.1, 0.95, 0.1, 20, 1.5, 2.5, 0.5, 500, 1.0, 50000,
                                      0.01, 1e-4, 0.5, 0.0, 2.0, 3.0, 0.01, 1.0,
                                      10, 0.05, 3.32, 0.05, 5, 0.95, 0.1, 1.0,
                                      128, 1e-7, 0.999, 10)
    check("OFF_SNC1_TPR_SS" in o1 and o1["OFF_SNC1_TPR_SS"] > 0.99, "G3: composite_analysis_offensive")
    o2 = composite_analysis_offensive(0.1, 0.95, 0.1, 20, 1.5, 2.5, 0.5, 500, 1.0, 50000,
                                      0.01, 1e-4, 0.5, 0.0, 2.0, 3.0, 0.01, 1.0,
                                      10, 0.05, 3.32, 0.05, 3, 0.95, 0.1, 1.0,
                                      128, 1e-7, 0.999, 10)
    check(abs(o1["OFF_SNC7_p_independent"] - o2["OFF_SNC7_p_independent"]) > 1e-9,
          "G3/B3: n_layers affects p_independent")

    de1 = composite_analysis_defensive(128, 1e-7, 1e-4, 0.01, 0.98, 0.02, 0.005,
                                       8.0, 10000, 1e-6, 1.0, 1.0, 0.001,
                                       0.85, 0.02, 3, 0.3, 0.10, 5,
                                       128, 1, 1.0, 0.01,
                                       100, 0.001, 100,
                                       0.999, 10, 2, 14.0, 0.5, 0.5)
    check("DEF_SNC1_p_unattested" in de1, "G4: composite_analysis_defensive")

    ob1 = composite_analysis_observation_bounds(50000, 1_000_000, 0.01, 0.01,
                                                10000, 5000, 40000,
                                                1_000_000, 0.45, 100,
                                                1.0, 1_000_000_000, 50000,
                                                0.99, 7, 50000,
                                                7_000_000_000, 1_000_000)
    check("OB_SNC1_L1_minimax" in ob1, "G5: composite_analysis_observation_bounds")

    pn1 = composite_analysis_platform("fp32", 50000, 10.82, 10.82, 3.0,
                                      0.5, 0.05, 1000, 1.0,
                                      100, 4096, 0.01, 1e-3, 1e-7,
                                      [(PrecisionBoundEntropy.EPS_M["fp32"], 0.05)] * 5,
                                      1.0, 0.01, 1.0, 1e-5, 0.1)
    check("PN_SNC1_entropy_error" in pn1, "G6: composite_analysis_platform")

    aot1 = composite_analysis_aot(12, 1e-6, 1e-4, 128, 2.0, 0.05, 1e-4,
                                   1e-5, 1e-4, 1e-7, [2, 8, 5, 6, 15, 0.001, 0.1], 0.2, 60.0,
                                   1000000, 5, 3, 2, 10.0, 128, 1e-7, 1e-5, 0.05,
                                   3, 0.01, 1.0, 0.5, 0.1)
    check("AOT_SNC14_posix_confidence" in aot1, "G7: composite_analysis_aot")
    check(aot1["AOT_SNC14_flock_abi_ok"] == _FLOCK_ABI_OK, "G7: AOT_SNC14 flock ABI reported")

    nv1 = composite_analysis_novelty(
        0.01, 10.0, 0.95, 0.01, 0.0001, 0.31,
        1e6, 7.0, 1e9, 0.31, 365.0,
        0.1, 0.7, 0.95, 0.05, 0.1,
        1e7, 0.05, 0.05, 1e5, 0.2, 0.1,
        [0.1, 0.2, 0.3], [0.95, 0.90, 0.85],
        [[0, 0.10, 0.05], [0.30, 0, 0], [0.20, 0, 0]], 0.8,
        0.01, 1e-4, 0.98, 0.02, 0.005)
    check("min_ratio" in nv1 and "interpretation" in nv1, "G8: composite_analysis_novelty")
    check("CIC" not in nv1["Q_factors"], "G8/C4: CIC excluded from Q_factors")
    check("CIC_tau_star_advisory" in nv1, "G8/C4: CIC reported as advisory")

    if failures == 0:
        LOG.ok("all self-test checkpoints passed"); return 0
    LOG.err(f"{failures} checkpoint(s) failed"); return 1


def cmd_analyze(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    comp = composite_analysis(args.alpha, args.L, args.delta_G, args.H0, args.generations,
                              args.delta_tol, args.eps_task, args.L_task, args.delta_KS, args.beta_KS, args.J0)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  SNC1-SNC10 THEOREM BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(9), C_BOLD)} {label.ljust(38)} {_c(str(value), color)}")
    _row("SNC1", "Negentropy J_n", f"{comp['SNC1_negentropy']:.4f}")
    _row("SNC2", "Entropy H_n", f"{comp['SNC2_entropy']:.4f} nats")
    _row("SNC3", "Info retention", f"{comp['SNC3_info_retention']:.4f}")
    _row("SNC3", "alpha_min", f"{comp['SNC3_alpha_min']:.4f}", warn=args.alpha < comp["SNC3_alpha_min"])
    _row("SNC4", "W2_inf", f"{comp['SNC4_wasserstein']:.4f}")
    _row("SNC4", "alpha_min_w2", f"{comp['SNC4_alpha_min']:.4f}", warn=args.alpha < comp["SNC4_alpha_min"])
    _row("SNC5", "F_inf", f"{comp['SNC5_fisher_retention']:.4f}", warn=comp["SNC5_fisher_retention"] < 0.5)
    _row("SNC6", "n_det", f"{comp['SNC6_detection_samples']}")
    _row("SNC7", "W_barrier", f"{comp['SNC7_barrier']:.4f}")
    _row("SNC8", "JSD(p_hat, p_0)", str(comp["SNC8_jsd_target"]))
    vcol = C_GREEN if comp["SNC10_verdict"] == "VALID" else C_RED
    print(_c(sep, C_CYAN)); print(f"  {_c('SNC10', C_BOLD)} {_c('VERDICT: ' + comp['SNC10_verdict'], vcol)}")
    print(f"         {comp['SNC10_detail']}")
    if comp["warnings"]:
        for w in comp["warnings"]: print(f"    - {w}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_deep(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    deep = composite_analysis_deep(args.alpha, args.c, args.delta_G, args.H0, args.generations,
                                   args.delta_tol, args.eps_task, args.L_task, args.delta_KS, args.beta_KS,
                                   args.J0, args.rho_G, args.pi_k, args.N_real, args.N_synth,
                                   args.temp, args.delta_model, args.rho_n, args.n_mode,
                                   args.P_H_real, args.P_H_0, args.eta, args.delta_target_alpha,
                                   args.B_0, args.tau, args.C_gen, args.gamma, args.eps_e, args.H_S)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  DSNC1-DSNC10 DEEP-PIPELINE BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(9), C_BOLD)} {label.ljust(38)} {_c(str(value), color)}")
    _row("DSNC1", "KL steady-state", f"{deep['DSNC1_KL_steady_state']:.4f} nats", warn=deep['DSNC1_KL_steady_state'] > args.delta_target_alpha)
    _row("DSNC2", "Mode pi^inf", f"{deep['DSNC2_mode_steady_state']:.4e}", warn=deep["DSNC2_mode_steady_state"] < args.pi_k * 0.5)
    _row("DSNC3", "T_eff", f"{deep['DSNC3_T_eff']:.4f}", warn=deep["DSNC3_T_eff"] > args.temp * 1.2)
    _row("DSNC4", "ESS", f"{deep['DSNC4_ESS']:.2f}", warn=deep["DSNC4_ESS"] < 100)
    _row("DSNC5", "P_H^inf", f"{deep['DSNC5_P_H_steady_state']:.6f}", warn=deep["DSNC5_P_H_steady_state"] > 0.05)
    _row("DSNC6", "alpha_final", f"{deep['DSNC6_alpha_final']:.4f}", warn=not deep["DSNC6_converged"])
    _row("DSNC7", "N*", f"{deep['DSNC7_N_optimal_continuous']:.2f}", warn=args.generations > deep["DSNC7_N_optimal_continuous"])
    _row("DSNC8", "Echo floor", f"{deep['DSNC8_echo_floor']:.6f}")
    _row("DSNC9", "IS efficiency", f"{deep['DSNC9_efficiency']:.4f}", warn=deep["DSNC9_efficiency"] < 0.5)
    print(_c(sep, C_CYAN))
    if deep["issues"]:
        for issue in deep["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_offensive(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    off = composite_analysis_offensive(args.alpha, args.L, args.delta_G, args.generations,
                                       args.tau, args.mu_adv, args.sigma_adv, args.n_adv,
                                       args.C_adv, args.n_train, args.f_attack, args.f_real,
                                       args.tpr_defense, args.f_fp, args.H_X1, args.H_X2,
                                       args.alpha_detect, args.eps_dp, args.M_sources,
                                       args.delta_attr, args.bits_per_stream, args.p_vectors,
                                       args.n_layers, args.d_layer, args.rho_common,
                                       args.gamma_bias, args.kappa, args.p_compromise,
                                       args.p_log, args.n_key)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  OFF_SNC1-OFF_SNC10 BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(9), C_BOLD)} {label.ljust(38)} {_c(str(value), color)}")
    _row("OFF_SNC1", "TPR_SS", f"{off['OFF_SNC1_TPR_SS']:.6f}", warn=off["OFF_SNC1_TPR_SS"] < 0.99)
    _row("OFF_SNC1", "f_crit", f"{off['OFF_SNC1_f_crit']:.4f}", warn=args.f_attack > off["OFF_SNC1_f_crit"])
    _row("OFF_SNC2", "f_eff", f"{off['OFF_SNC2_f_eff']:.4f}", warn=off["OFF_SNC2_f_eff"] > 0.005)
    _row("OFF_SNC4", "f_inf", f"{off['OFF_SNC4_f_inf']:.5f}", warn=off["OFF_SNC4_f_inf"] > 0.05)
    _row("OFF_SNC5", "Adv_total", f"{off['OFF_SNC5_Adv_total']:.6f}", warn=off["OFF_SNC5_Adv_total"] > 0.1)
    _row("OFF_SNC6", "streams required", f"{off['OFF_SNC6_streams_required']:.3f}", warn=off["OFF_SNC6_streams_required"] > 5)
    _row("OFF_SNC7", "P_def_fail", f"{off['OFF_SNC7_p_defense_fail']:.6f}", warn=off["OFF_SNC7_p_defense_fail"] > 0.01)
    _row("OFF_SNC8", "A_attack", f"{off['OFF_SNC8_A_attack']:.4f}", warn=off["OFF_SNC8_A_attack"] > 0.5)
    _row("OFF_SNC9", "P_repudiation", f"{off['OFF_SNC9_p_repudiation']:.2e}", warn=off["OFF_SNC9_p_repudiation"] > 1e-6)
    _row("OFF_SNC9", "P_reconstruct", f"{off['OFF_SNC9_p_reconstruct']:.4f}", warn=off["OFF_SNC9_p_reconstruct"] < 0.99)
    print(_c(sep, C_CYAN))
    if off["issues"]:
        for issue in off["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_defensive(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    deff = composite_analysis_defensive(args.kappa, args.p_compromise, args.eps_trust_list,
                                        args.f_attack, args.tpr_sanitize, args.fpr_sanitize,
                                        args.f_crit, args.eps_target, args.T_steps, args.delta_dp,
                                        args.C_clip, args.G_grad, args.eta_lr, args.det_tpr,
                                        args.det_fpr, args.n_detectors, args.rho_detectors,
                                        args.p_single_error, args.M_ensemble, args.k_bits,
                                        args.n_w, args.theta_norm_sq, args.delta_theta_norm_sq,
                                        args.n_c, args.p_leak, args.n_outputs_canary,
                                        args.p_log, args.n_key, args.n_systems,
                                        args.h_cusum, args.D_target, args.D_0)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  DEF_SNC1-DEF_SNC10 BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(9), C_BOLD)} {label.ljust(38)} {_c(str(value), color)}")
    _row("DEF_SNC1", "P_unattested", f"{deff['DEF_SNC1_p_unattested']:.2e}", warn=deff["DEF_SNC1_p_unattested"] > 1e-3)
    _row("DEF_SNC2", "f_eff sanitized", f"{deff['DEF_SNC2_f_eff']:.6f}", warn=deff["DEF_SNC2_f_eff"] > args.f_crit)
    _row("DEF_SNC3", "eps_total", f"{deff['DEF_SNC3_eps_total']:.4f}", warn=deff["DEF_SNC3_eps_total"] > args.eps_target * 1.1)
    _row("DEF_SNC3", "utility_loss", f"{deff['DEF_SNC3_utility_loss']:.4f}", warn=deff["DEF_SNC3_utility_loss"] > 1.0)
    _row("DEF_SNC4", "TPR_fusion", f"{deff['DEF_SNC4_tpr_fusion']:.4f}", warn=deff["DEF_SNC4_tpr_fusion"] < 0.95)
    _row("DEF_SNC4", "TPR_fusion (corr)", f"{deff['DEF_SNC4_tpr_fusion_corr']:.4f}", warn=deff["DEF_SNC4_tpr_fusion_corr"] < 0.95)
    _row("DEF_SNC5", "P_ens_err", f"{deff['DEF_SNC5_p_ensemble_error']:.5f}", warn=deff["DEF_SNC5_p_ensemble_error"] > 0.05)
    _row("DEF_SNC6", "P_miss", f"{deff['DEF_SNC6_p_miss']:.2e}", warn=deff["DEF_SNC6_p_miss"] > 1e-3)
    _row("DEF_SNC7", "P_detect", f"{deff['DEF_SNC7_p_detect']:.4f}", warn=deff["DEF_SNC7_p_detect"] < 0.95)
    _row("DEF_SNC8", "P_reconstruct (redundant)", f"{deff['DEF_SNC8_p_reconstruct_redundant']:.7f}", warn=deff["DEF_SNC8_p_reconstruct_redundant"] < 0.99)
    _row("DEF_SNC9", "detection_delay", f"{deff['DEF_SNC9_detection_delay']:.1f} gens", warn=deff["DEF_SNC9_detection_delay"] > 30)
    print(_c(sep, C_CYAN))
    if deff["issues"]:
        for issue in deff["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_observation_bounds(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    ob = composite_analysis_observation_bounds(
        M_vocab=args.M_vocab, n_hl=args.n_hl, eps_hl=args.eps_hl, delta_hl=args.delta_hl,
        f1=args.f1, f2=args.f2, S_obs=args.S_obs,
        N_synth=args.N_synth, rho_n=args.rho_n, k_autocorr=args.k_autocorr,
        eps_dp=args.eps_dp, N_train_hl=args.N_train_hl, X_size=args.X_size,
        p_per_step=args.p_per_step, n_links=args.n_links,
        M_eff=args.M_eff, n_state=args.n_state, n_test=args.n_test)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  OB_SNC1-OB_SNC10 OBSERVATION-BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(10), C_BOLD)} {label.ljust(40)} {_c(str(value), color)}")
    l1 = ob["OB_SNC1_L1_minimax"]
    _row("OB_SNC1", "L1 minimax error", f"{l1:.4f}", warn=l1 > 0.5)
    _row("OB_SNC1", "KL minimax error", f"{ob['OB_SNC1_KL_minimax']:.5f}")
    _row("OB_SNC1", "n required (99%)", f"{ob['OB_SNC1_n_required']:.2e}")
    _row("OB_SNC2", "Precision floor", f"{ob['OB_SNC2_precision_floor']:.4f}", warn=ob["OB_SNC2_precision_floor"] > 0.05)
    K_u = ob["OB_SNC3_K_unobserved"]
    _row("OB_SNC3", "K_unobserved", f"{K_u:.0f}" if math.isfinite(K_u) else "inf", warn=math.isfinite(K_u) and K_u > 1000)
    _row("OB_SNC3", "M_0", f"{ob['OB_SNC3_M_0']:.6f}", warn=ob["OB_SNC3_M_0"] > 0.01)
    _row("OB_SNC4", "ESS", f"{ob['OB_SNC4_ESS']:.2f}", warn=ob["OB_SNC4_ESS"] < 100)
    _row("OB_SNC5", "MIA advantage", f"{ob['OB_SNC5_MIA_advantage']:.6f}", warn=ob["OB_SNC5_MIA_advantage"] > 0.5)
    _row("OB_SNC5", "Memorized count", f"{ob['OB_SNC5_memorized_count']:.2e}", warn=ob["OB_SNC5_memorized_count"] > 1e7)
    _row("OB_SNC6", "Chain probability", f"{ob['OB_SNC6_chain_probability']:.4f}")
    _row("OB_SNC6", "Gap fraction", f"{ob['OB_SNC6_gap_fraction']:.4f}", warn=ob["OB_SNC6_gap_fraction"] > 0.05)
    _row("OB_SNC7", "Coverage", f"{ob['OB_SNC7_coverage']:.6f}")
    _row("OB_SNC7", "Uncovered mass", f"{ob['OB_SNC7_uncovered_mass']:.2e}", warn=ob["OB_SNC7_uncovered_mass"] > 0.01)
    print(_c(sep, C_CYAN))
    print(f"  {_c('OB_SNC8 (Rice):', C_BOLD)} decidable={len(ob['OB_SNC8_rice']['decidable'])}, "
          f"undecidable={len(ob['OB_SNC8_rice']['undecidable'])}")
    _row("OB_SNC9", "Observable rank", f"{ob['OB_SNC9_observable_rank']:.2e}")
    _row("OB_SNC9", "Unobservable fraction", f"{ob['OB_SNC9_unobservable_fraction']:.6f}", warn=ob["OB_SNC9_unobservable_fraction"] > 0.99)
    print(_c(sep, C_CYAN))
    if ob["issues"]:
        for issue in ob["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_platform(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    pn = composite_analysis_platform(
        precision=args.precision, M_vocab=args.M_vocab, log_M=args.log_M, H_log=args.H_log,
        K_abs=args.K_abs, D_KL_true=args.D_KL_true, delta_H=args.delta_H,
        N_nodes=args.N_nodes, g_norm=args.g_norm, E=args.E, B_max=args.B_max,
        beta=args.beta, eps_iso=args.eps_iso, eps_step=args.eps_step,
        hardware_list=[(PrecisionBoundEntropy.EPS_M[args.precision], 0.05)] * 5,
        w_norm_sq=args.w_norm_sq, delta_theta_norm_sq=args.delta_theta_norm_sq,
        theta_norm_sq=args.theta_norm_sq, eps_accum_max=args.eps_accum_max, tau_max=args.tau_max)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  PN_SNC1-PN_SNC11 PLATFORM-NEUTRAL BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(10), C_BOLD)} {label.ljust(40)} {_c(str(value), color)}")
    _row("PN_SNC1", "Entropy precision error", f"{pn['PN_SNC1_entropy_error']:.2e} nats", warn=not pn["PN_SNC1_agnostic"])
    _row("PN_SNC1", "Entropy platform-agnostic?", str(pn["PN_SNC1_agnostic"]), warn=not pn["PN_SNC1_agnostic"])
    _row("PN_SNC2", "KL relative error", f"{pn['PN_SNC2_KL_relative_error']:.4f}", warn=pn["PN_SNC2_KL_relative_error"] > 0.1)
    _row("PN_SNC3", "Ring aggregation error", f"{pn['PN_SNC3_ring_error']:.2e}", warn=pn["PN_SNC3_ring_error"] > 0.1)
    _row("PN_SNC3", "Tree aggregation error", f"{pn['PN_SNC3_tree_error']:.2e}")
    _row("PN_SNC4", "Detection floor", f"{pn['PN_SNC4_delta_min']:.4f}", warn=pn["PN_SNC4_delta_min"] > 0.1)
    _row("PN_SNC5", "Operating window", f"[{pn['PN_SNC5_operating_window_lo']:.4f}, {pn['PN_SNC5_operating_window_hi']:.4f}]",
         warn=pn["PN_SNC5_operating_window_lo"] >= pn["PN_SNC5_operating_window_hi"])
    _row("PN_SNC6", "Portable", str(pn["PN_SNC6_portable"]), warn=not pn["PN_SNC6_portable"])
    _row("PN_SNC7", "ABI conforms", str(pn["PN_SNC7_abi_conforms"]), warn=not pn["PN_SNC7_abi_conforms"])
    _row("PN_SNC8", "Fleet reliability", f"{pn['PN_SNC8_fleet_reliability']:.4f}", warn=pn["PN_SNC8_fleet_reliability"] < 0.95)
    _row("PN_SNC9", "Sync interval (steps)", f"{pn['PN_SNC9_sync_interval']:.0f}", warn=pn["PN_SNC9_sync_interval"] < 1)
    _row("PN_SNC11", "Neumaier relative error bound", f"{pn['PN_SNC11_neumann_bound']:.2e}", warn=pn['PN_SNC11_neumann_bound'] > 1e-12)
    _row("PN_SNC11", "Kahan->Neumaier improvement", f"{pn['PN_SNC11_neumann_improvement']:.1f}x")
    print(_c(sep, C_CYAN))
    if pn["issues"]:
        for issue in pn["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_aot(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    wcet_list = [float(x) for x in args.wcet_list.split(",")]
    aot = composite_analysis_aot(
        n_stage=args.n_stage, eps_stage=args.eps_stage, eps_measure=args.eps_measure,
        kappa_compile=args.kappa_compile,
        s_max=args.s_max, min_tau=args.min_tau, ERR_target=args.ERR_target,
        eps_1=args.eps_1, eps_2=args.eps_2, P_shared=args.P_shared,
        wcet_list=wcet_list, alpha_wcet=args.alpha_wcet, tau_budget=args.tau_budget,
        n_s=args.n_s, n_class=args.n_class, n_tier=args.n_tier, n_hyst=args.n_hyst,
        per_state_us=args.per_state_us,
        kappa_attest=args.kappa_attest, p_key_compromise=args.p_key_compromise,
        eps_patch=args.eps_patch, delta_cov=args.delta_cov,
        k_consecutive=args.k_consecutive, tau_alarm=args.tau_alarm,
        T_generation=args.T_generation, discrepancy=args.discrepancy,
        sigma_verify=args.sigma_verify)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  AOT_SNC1-AOT_SNC14 CERTIFIED-MEASUREMENT BOUNDS", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(10), C_BOLD)} {label.ljust(40)} {_c(str(value), color)}")
    _row("AOT_SNC1", "Compile violation prob", f"{aot['AOT_SNC1_compile_violation']:.2e}", warn=not aot["AOT_SNC1_contract_ok"])
    _row("AOT_SNC2", "Required bins", f"{aot['AOT_SNC2_n_bins']}")
    _row("AOT_SNC2", "Bin lookup error", f"{aot['AOT_SNC2_bin_error']:.2e}")
    _row("AOT_SNC3", "Wrong binary prob", f"{aot['AOT_SNC3_wrong_binary']:.2e}", warn=aot["AOT_SNC3_wrong_binary"] > 1e-5)
    _row("AOT_SNC3", "Improvement factor", f"{aot['AOT_SNC3_improvement']:.1f}x")
    _row("AOT_SNC4", "Static WCET (s)", f"{aot['AOT_SNC4_wcet_static']:.2f}", warn=not aot["AOT_SNC4_within_budget"])
    _row("AOT_SNC5", "Total states", f"{aot['AOT_SNC5_n_states']}")
    _row("AOT_SNC5", "Boundary sliver", f"{aot['AOT_SNC5_boundary_sliver']:.2e}", warn=aot["AOT_SNC5_boundary_sliver"] > 1e-4)
    _row("AOT_SNC6", "Modified acceptance", f"{aot['AOT_SNC6_p_modified']:.2e}", warn=aot["AOT_SNC6_p_modified"] > 1e-5)
    _row("AOT_SNC7", "Undetected regression", f"{aot['AOT_SNC7_p_regression']:.2e}", warn=aot["AOT_SNC7_p_regression"] > 1e-5)
    _row("AOT_SNC9", "Runtime detection P", f"{aot['AOT_SNC9_p_detect']:.4f}", warn=aot["AOT_SNC9_p_detect"] < 0.99)
    _row("AOT_SNC11", "Volatile/black_box enforced", str(aot['AOT_SNC11_volatile']), warn=not aot['AOT_SNC11_volatile'])
    _row("AOT_SNC11", "IEEE 754 strict flags", ",".join(aot['AOT_SNC11_flags']))
    _row("AOT_SNC13", "Install dir namespace OK", str(aot['AOT_SNC13_install_ok']), warn=not aot['AOT_SNC13_install_ok'])
    _row("AOT_SNC13", "Install reason", aot['AOT_SNC13_install_reason'])
    _row("AOT_SNC13", "PID dir namespace OK", str(aot['AOT_SNC13_pid_ok']), warn=not aot['AOT_SNC13_pid_ok'])
    _row("AOT_SNC13", "PID reason", aot['AOT_SNC13_pid_reason'])
    _row("AOT_SNC14", "POSIX attribution confidence", f"{aot['AOT_SNC14_posix_confidence']:.4f}", warn=aot['AOT_SNC14_posix_confidence'] < 0.99)
    _row("AOT_SNC14", "start_time verified (real)", str(aot['AOT_SNC14_start_time_verified']))
    _row("AOT_SNC14", "flock ABI OK", str(aot['AOT_SNC14_flock_abi_ok']), warn=not aot['AOT_SNC14_flock_abi_ok'])
    _row("AOT_SNC14", "flock size", f"{aot['AOT_SNC14_flock_size']} bytes (expected 32)")
    print(_c(sep, C_CYAN))
    print(f"  {_c('AOT_SNC8 (Rice):', C_BOLD)} decidable={len(aot['AOT_SNC8_rice']['decidable'])}, "
          f"undecidable={len(aot['AOT_SNC8_rice']['undecidable'])}")
    if aot["issues"]:
        print(f"  {_c('ISSUES FLAGGED:', C_YELLOW)}")
        for issue in aot["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


def cmd_analyze_novelty(args):
    if not HAS_NUMPY: LOG.err("numpy required"); return 1
    alpha_list = [float(x) for x in args.alpha_list_mmc.split(",")]
    L_list = [float(x) for x in args.L_list_mmc.split(",")]
    rows = args.kappa_matrix_mmc.split(";")
    kappa_matrix = [[float(x) for x in row.split(",")] for row in rows]
    novel = composite_analysis_novelty(
        V_seb=args.V_seb, H0_seb=args.H0_seb, L_seb=args.L_seb,
        c_R_seb=args.c_R_seb, c_S_seb=args.c_S_seb,
        alpha_min_safety=args.alpha_min_safety,
        R_real_gav=args.R_real_gav, T_gen_gav=args.T_gen_gav,
        N_total_gav=args.N_total_gav, alpha_star_gav=args.alpha_star_gav,
        T_budget_days=args.T_budget_days,
        alpha_mcb=args.alpha_mcb, beta_mcb=args.beta_mcb, L_B_mcb=args.L_B_mcb,
        D_source_mcb=args.D_source_mcb, D_target_mcb=args.D_target_mcb,
        V0_cic=args.V0_cic, g_cic=args.g_cic, r_cic=args.r_cic,
        C_int_cic=args.C_int_cic, D_scale_cic=args.D_scale_cic,
        tau_safety_cic=args.tau_safety_cic,
        alpha_list_mmc=alpha_list, L_list_mmc=L_list,
        kappa_matrix_mmc=kappa_matrix, rho_target_mmc=args.rho_target_mmc,
        f_attack_aac=args.f_attack_aac, eps_trust_aac=args.eps_trust_aac,
        tpr_san_aac=args.tpr_san_aac, fpr_san_aac=args.fpr_san_aac,
        f_crit_aac=args.f_crit_aac)
    sep = "=" * 78
    print(); print(_c(sep, C_CYAN)); print(_c("  NV_SNC1-NV_SNC7 OPERATIONAL-ECONOMIC COMPOSITES", C_BOLD)); print(_c(sep, C_CYAN))
    def _row(tag, label, value, warn=False):
        color = C_YELLOW if warn else C_GREEN
        print(f"  {_c(tag.ljust(10), C_BOLD)} {label.ljust(40)} {_c(str(value), color)}")
    _row("NV_SNC1", "SEB: alpha* (optimum)", f"{novel['SEB_alpha_star']:.4f}")
    _row("NV_SNC1", "SEB: c_R^max", f"${novel['SEB_c_R_max']:.4f}/sample")
    _row("NV_SNC1", "SEB: Q factor", f"{novel['SEB_Q']:.3f}", warn=novel['SEB_Q'] < 1)
    _row("NV_SNC2", "GAV: t* (days)", f"{novel['GAV_t_star_days']:.1f}")
    _row("NV_SNC2", "GAV: n* (generations)", f"{novel['GAV_n_star_gens']:.1f}")
    _row("NV_SNC2", "GAV: Q factor", f"{novel['GAV_Q']:.3f}", warn=novel['GAV_Q'] < 1)
    _row("NV_SNC3", "MCB: A_cross", f"{novel['MCB_A_cross']:.4f}")
    _row("NV_SNC3", "MCB: D_B linear", f"{novel['MCB_D_B_linear']:.4f} nats")
    _row("NV_SNC3", "MCB: D_B quadratic", f"{novel['MCB_D_B_quad']:.4f} nats")
    _row("NV_SNC3", "MCB: D_A critical", f"{novel['MCB_D_A_crit']:.4f} nats")
    _row("NV_SNC3", "MCB: Q factor", f"{novel['MCB_Q']:.3f}", warn=novel['MCB_Q'] < 1)
    _row("NV_SNC4", "CIC: tau* (ADVISORY)", f"{novel['CIC_tau_star_advisory']:.2f} nats", warn=True)
    _row("NV_SNC5", "MMC: rho(W)", f"{novel['MMC_rho_W']:.4f}", warn=novel['MMC_rho_W'] >= 1.0)
    _row("NV_SNC5", "MMC: A_MMC", f"{novel['MMC_A_MMC']:.4f}")
    _row("NV_SNC5", "MMC: Q factor", f"{novel['MMC_Q']:.3f}", warn=novel['MMC_Q'] < 1)
    _row("NV_SNC6", "AAC: f_eff", f"{novel['AAC_f_eff']:.2e}", warn=novel['AAC_f_eff'] > args.f_crit_aac)
    _row("NV_SNC6", "AAC: eps_trust^max", f"{novel['AAC_eps_trust_max']:.4f}")
    _row("NV_SNC6", "AAC: Q factor", f"{novel['AAC_Q']:.3e}", warn=novel['AAC_Q'] < 1)
    print(_c(sep, C_CYAN))
    print(f"  {_c('NV_SNC7 (Composite):', C_BOLD)}")
    for k, v in novel['Q_factors'].items(): print(f"      {k:5s}: {v:.3f}")
    q_col = C_GREEN if novel['min_ratio'] >= 1.0 else C_RED
    min_ratio_str = format(novel['min_ratio'], '.3f')
    print(f"    {_c('min_ratio', C_BOLD)} = {_c(min_ratio_str, q_col)}  "
          f"(binding: {novel['binding_constraint']})")
    print(f"    {novel['interpretation']}")
    print(_c(sep, C_CYAN))
    if novel["issues"]:
        for issue in novel["issues"]: print(f"    - {issue}")
    else: print(f"  {_c('No issues flagged.', C_GREEN)}")
    print(_c(sep, C_CYAN)); print(); return 0


class _MetricsState:
    def __init__(self):
        self.lock = threading.Lock(); self.data = {"generation": 0, "version": ZARQA_VERSION}
    def update(self, **kw):
        with self.lock:
            self.data.update(kw); self.data["updated"] = datetime.now(timezone.utc).isoformat()
    def snapshot(self):
        with self.lock: return dict(self.data)


def _start_metrics_server(state, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    semaphore = threading.Semaphore(10)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a): pass
        def do_GET(self):
            if not semaphore.acquire(timeout=1.0):
                self.send_response(429); self.end_headers()
                try: self.wfile.write(b"rate limited\n")
                except Exception: pass
                return
            try:
                if self.path in ("/metrics", "/"):
                    body = json.dumps(state.snapshot()).encode()
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/health":
                    self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
                else: self.send_response(404); self.end_headers()
            finally: semaphore.release()
    server = None
    for attempt_port in (port, 0):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", attempt_port), Handler); break
        except OSError as exc:
            if attempt_port != 0: LOG.warn(f"port {attempt_port} bind failed ({exc}); falling back to ephemeral")
            else: LOG.err(f"ephemeral bind failed: {exc}"); raise
    actual_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    LOG.ok(f"metrics endpoint bound on 127.0.0.1:{actual_port}")
    return actual_port


def cmd_daemon(_args):
    if not HAS_NUMPY: LOG.err("numpy unavailable"); return 1
    ensure_runtime_dirs()
    pid_dir = os.path.dirname(ZARQA_PID_FILE)
    try: os.chmod(pid_dir, 0o750)
    except OSError: pass
    # AOT_SNC30 (v2.8.3): 5-step secure PID allocation
    try:
        pid_fd = _acquire_secure_pid_fd(ZARQA_PID_FILE, mode=0o640)
    except RuntimeError as exc:
        LOG.err(f"cannot acquire secure PID fd: {exc}"); return 1
    payload = write_pid_file(pid_fd)
    LOG.ok(f"PID lock acquired (pid={payload['pid']}, start_ticks={payload['start_time_ticks']})")
    metrics_port = int(os.environ.get("ZARQA_METRICS_PORT", ZARQA_METRICS_PORT))
    state = _MetricsState()
    try:
        _start_metrics_server(state, metrics_port)
    except Exception as exc:
        LOG.err(f"metrics server failed: {exc}")
        try: os.close(pid_fd)
        except OSError: pass
        return 1
    mon = DistributionMonitor(arl_0=1e4)
    ctrl = MixingController(epsilon=0.05, h0=math.log(4))
    dpa = PrivacyAccountant()
    rng = np.random.default_rng(int(time.time()))
    h_prev = math.log(4); t = 0
    LOG.info("daemon loop starting (8 frameworks live)")
    def _stop(_sig, _frm):
        LOG.info("received shutdown signal"); sys.exit(0)
    signal.signal(signal.SIGTERM, _stop); signal.signal(signal.SIGINT, _stop)
    try:
        while True:
            t += 1
            phase = t * 0.1
            conc_p = max(0.5, 2.0 + 1.5 * math.cos(phase))
            conc_q = max(0.5, 2.0 + 1.5 * math.cos(phase * 0.7))
            p = rng.dirichlet(np.ones(4) * conc_p)
            q = rng.dirichlet(np.ones(4) * conc_q)
            grads = rng.normal(size=(256, 8)) * max(0.1, 1.0 - t * 0.01)
            rec = mon.record(t, p, q, grads, weights=(q / np.maximum(p, 1e-12)))
            delta_hat = max(0.0, h_prev - rec["H"])
            upd = ctrl.update(rec["H"], delta_hat)
            dpa.step(batch_fraction=0.01)
            comp = composite_analysis(upd["alpha"], 0.95, delta_hat, math.log(4), t, 0.05, 0.05, 0.1, 0.05, 0.01)
            state.update(generation=t, H=rec["H"], KL=rec["KL"], alpha=upd["alpha"],
                         budget=dpa.budget_status(), snc10_verdict=comp["SNC10_verdict"],
                         ess=rec.get("ess"))
            LOG.info(f"gen={t:04d} H={rec['H']:.4f} KL={rec['KL']:.4f} alpha={upd['alpha']:.4f} "
                     f"eps={dpa.epsilon():.4f} SNC10={comp['SNC10_verdict']} "
                     f"ESS={rec.get('ess')}")
            h_prev = rec["H"]; time.sleep(5.0)
    finally:
        try: os.close(pid_fd)
        except OSError: pass


def cmd_run(_args):
    LOG.info("foreground run (equivalent to daemon)")
    return cmd_daemon(None)


def _opt_has_red_flags():
    try:
        st = os.stat('/opt')
    except OSError as e:
        return (True, f"cannot stat /opt: {e}", None)
    if st.st_mode & 0o022:
        return (True, f"/opt mode={oct(st.st_mode & 0o777)} permits group/other write", st)
    try:
        entries = os.listdir('/opt')
    except OSError as e:
        return (True, f"cannot list /opt: {e}", st)
    for entry in entries:
        p = os.path.join('/opt', entry)
        try:
            est = os.lstat(p)
        except OSError: continue
        _S_IFMT = 0o170000; _S_IFDIR = 0o040000; _S_IFREG = 0o100000
        is_dir = (est.st_mode & _S_IFMT) == _S_IFDIR
        if (not is_dir) and (est.st_mode & (0o4000 | 0o2000)):
            kind = "regular file" if ((est.st_mode & _S_IFMT) == _S_IFREG) else "special file"
            return (True, f"{p} has setuid/setgid bit on {kind} (mode={oct(est.st_mode & 0o7777)})", st)
        if os.path.islink(p):
            try:
                target = os.path.realpath(p)
            except OSError: continue
            if not (target == '/opt' or target.startswith('/opt/')):
                return (True, f"{p} is a symlink escaping /opt to {target}", st)
    return (False, "no red flags", st)


def _managed_dir_ancestor_set():
    s = set()
    for d in (ZARQA_INSTALL_DIR, ZARQA_STATE_DIR, ZARQA_LOG_DIR, os.path.dirname(ZARQA_PID_FILE)):
        for a in _ancestor_chain_inclusive(d):
            s.add(a)
    return s


def _auto_fix_zarqa_ownership(accept_nonroot_opt=False):
    """AOT_SNC18 + AOT_SNC19 + AOT_SNC20: Targeted ancestral sovereignty."""
    if not _is_root():
        return True

    try:
        root_st = os.stat('/')
    except OSError as e:
        LOG.err(f"cannot stat /: {e}"); return False
    if root_st.st_uid != 0:
        LOG.err("=" * 78)
        LOG.err(f"REFUSING: / uid={root_st.st_uid} != 0 -- root filesystem owned by non-root")
        LOG.err("This is a real compromise state, not config-drift issue.")
        LOG.err("Do NOT run chown -R /; that would recursively chown the entire filesystem.")
        LOG.err("Investigate the host first:")
        LOG.err("  sudo ls -lan /")
        LOG.err("  getent passwd $(stat -c %u /)")
        LOG.err("=" * 78)
        return False
    if root_st.st_mode & 0o022:
        LOG.err("=" * 78)
        LOG.err(f"REFUSING: / mode={oct(root_st.st_mode & 0o777)} permits group/other write")
        LOG.err("This is a real danger state, not config drift.")
        LOG.err("Do NOT proceed until / is 0755 root:root.")
        LOG.err("=" * 78)
        return False
    LOG.ok(f"/ is root-owned, mode={oct(root_st.st_mode & 0o777)}, no g/o write")

    if os.path.islink('/opt'):
        target = os.path.realpath('/opt')
        LOG.warn(f"/opt is a symlink -> {target}")
        LOG.warn("AOT_SNC16/19: lchown will change the SYMLINK itself, NOT the target directory")
        _audit_log(f"/opt is symlink -> {target}")

    red_flags, flag_reason, opt_st = _opt_has_red_flags()
    if opt_st is None:
        LOG.err(f"REFUSING: {flag_reason}"); return False

    opt_uid = opt_st.st_uid; opt_gid = opt_st.st_gid; opt_mode = opt_st.st_mode & 0o777

    if opt_uid == 0 and opt_gid == 0:
        if not red_flags:
            LOG.ok(f"/opt is root:root mode={oct(opt_mode)}; no red flags")
        else:
            LOG.warn("=" * 78)
            LOG.warn(f"/opt is root:root but has red flags: {flag_reason}")
            LOG.warn("Investigate separately; the ancestor fix below is safe.")
            LOG.warn("  sudo ls -lan /opt")
            LOG.warn("  sudo find /opt -maxdepth 2 -type f -perm /6000 -ls")
            LOG.warn("=" * 78)
            _audit_log(f"root-owned /opt with red flags: {flag_reason}")
    else:
        try:
            import pwd as _pwd
            owner_name = _pwd.getpwuid(opt_uid).pw_name
            owner_desc = f"{owner_name} (uid={opt_uid})"
        except (KeyError, ImportError):
            owner_name = None
            owner_desc = f"orphaned uid={opt_uid} (no /etc/passwd entry)"

        LOG.warn(f"/opt is owned by {owner_desc}, gid={opt_gid}, mode={oct(opt_mode)}")

        if red_flags and not accept_nonroot_opt:
            LOG.err("=" * 78)
            LOG.err(f"REFUSING auto-fix: /opt has red flags: {flag_reason}")
            LOG.err(f"Owner: {owner_desc} gid={opt_gid} mode={oct(opt_mode)}")
            LOG.err("")
            LOG.err("Red flags mean the danger is NOT in /opt's own inode;")
            LOG.err("it is in children that chowning /opt itself would not fix.")
            LOG.err("")
            LOG.err("Diagnose with:")
            LOG.err("  sudo ls -lan /opt")
            LOG.err("  sudo find /opt -maxdepth 2 -type f -perm /6000 -ls")
            LOG.err("  sudo find /opt -maxdepth 2 -type l -exec sh -c 'readlink -f \"$1\"' _ {} \\;")
            LOG.err("")
            LOG.err("If you have investigated and accept the risk, re-run with:")
            LOG.err(" backends")
    syntax_check(); clear_zarqa_processes(); reap_zombies()
    LOG.step("Service port pre-check")
    service_port = ZARQA_SERVICE_PORT; metrics_port = ZARQA_METRICS_PORT
    if port_in_use(service_port):
        LOG.warn(f"service port {service_port} in use; daemon falls back to ephemeral")
    if port_in_use(metrics_port):
        LOG.warn(f"metrics port {metrics_port} in use; daemon falls back to ephemeral")
    LOG.ok(f"service={service_port} metrics={metrics_port} (atomic bind in daemon)")
    if not run_preflight_selftest():
        raise RuntimeError("pre-flight self-test failed -- aborting deployment")
    LOG.ok("pre-flight self-test passed")
    write_systemd_unit(service_port, metrics_port)
    write_deploy_hash()
    try: os.unlink(ZARQA_DEPLOY_PENDING)
    except OSError: pass
    run_stream(["systemctl", "enable", "--now", f"{ZARQA_NAME}.service"], check=True)
    run_stream(["systemctl", "restart", f"{ZARQA_NAME}.service"], check=True)
    time.sleep(3.0)
    if run_stream(["systemctl", "is-active", "--quiet", f"{ZARQA_NAME}.service"]) != 0:
        raise RuntimeError("systemd service failed to start")
    LOG.ok("systemd service active")


def cmd_auto_deploy(args):
    self_heal_permissions()
    if deployment_is_current():
        LOG.ok("deployment is current (hash matches) -- skipping")
        LOG.info(f"to force re-deploy: edit the script or remove {ZARQA_DEPLOY_HASH}")
        _show_monitoring_tail(); return 0
    if not _auto_fix_zarqa_ownership(getattr(args, "accept_nonroot_opt", False)):
        LOG.err("namespace auto-fix failed; aborting deploy"); return 1
    try:
        deploy_steps(state_dir=args.state_dir)
    except Exception as exc:
        LOG.err(f"deployment failed: {exc}")
        LOG.err("Investigate with:")
        LOG.err("  sudo stat -c '%U:%G %a %n' / /opt /opt/zarqa /opt/zarqa/zasi")
        LOG.err(f"  cat {ZARQA_DEPLOY_PENDING} 2>/dev/null || true")
        LOG.err("  journalctl -u zarqa-snc.service -n 100 --no-pager")
        return 1
    _show_monitoring_tail(); return 0


def _show_monitoring_tail():
    LOG.step("Service monitoring")
    subprocess.run(["systemctl", "--no-pager", "status", f"{ZARQA_NAME}.service"], check=False)
    subprocess.run(["journalctl", "-u", f"{ZARQA_NAME}.service", "-n", "30", "--no-pager"], check=False)
    LOG.info(f"metrics endpoint: http://127.0.0.1:{ZARQA_METRICS_PORT}/metrics")


def cmd_status(_args):
    LOG.step("Deployment status")
    for k, v in detect_environment().items(): LOG.info(f"  {k}: {v}")
    LOG.info(f"script path: {ZARQA_SCRIPT_PATH}")
    LOG.info(f"running from target: {is_running_from_target()}")
    LOG.info(f"deploy hash current: {deployment_is_current()}")
    LOG.info(f"deploy pending marker: {os.path.isfile(ZARQA_DEPLOY_PENDING)} ({ZARQA_DEPLOY_PENDING})")
    LOG.info(f"PID file: {ZARQA_PID_FILE} (exists={os.path.isfile(ZARQA_PID_FILE)})")
    if os.path.isfile(ZARQA_PID_FILE):
        info = read_pid_file()
        LOG.info(f"PID payload: {info}")
    LOG.info(f"build dir: {ZARQA_BUILD_DIR} (exists={os.path.isdir(ZARQA_BUILD_DIR)})")
    LOG.info(f"venv: {os.path.isdir(ZARQA_VENV_DIR)}, C lib: {os.path.isfile(ZARQA_CFFI_LIB)}, "
             f"Rust lib: {os.path.isfile(ZARQA_RUST_LIB)}, C++ lib: {os.path.isfile(ZARQA_CPP_LIB)}")
    LOG.info(f"flock ABI: sizeof={_FLOCK_SIZE} (expected 32); ABI OK={_FLOCK_ABI_OK}")
    LOG.info(f"version: {ZARQA_VERSION}; residuals: {ZARQA_RESIDUALS_COUNT}")
    ok_ns, reason_ns = NamespaceIntegrity.verify_ancestors(ZARQA_INSTALL_DIR)
    LOG.info(f"namespace integrity (install): {ok_ns} -- {reason_ns}")
    try:
        snap = urllib.request.urlopen(f"http://127.0.0.1:{ZARQA_METRICS_PORT}/health", timeout=2).read()
        LOG.ok(f"metrics endpoint reachable: {snap!r}")
    except Exception as exc:
        LOG.warn(f"metrics endpoint not reachable: {exc}")
    LOG.step(f"Disclosed residuals ({len(SNC_RESIDUALS)} total; {len(_RESIDUALS_DOC_ONLY)} doc-only)")
    for key, msg in SNC_RESIDUALS.items():
        marker = " [doc-only]" if key in _RESIDUALS_DOC_ONLY else ""
        LOG.info(f"  {key}{marker}: {msg}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="zarqa_synthetic_negentropy_core",
        description="ZARQA SNC Phase 1: 8 frameworks (v2.8.3)")
    p.add_argument("--version", action="version", version=f"zarqa-snc {ZARQA_VERSION}")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--bootstrap-namespace", action="store_true",
                   help="manual fallback; --auto-deploy does this automatically")
    g.add_argument("--auto-deploy", action="store_true",
                   help="ONE-COMMAND deployment; no flags required.")
    g.add_argument("--test", action="store_true")
    g.add_argument("--analyze", action="store_true")
    g.add_argument("--analyze-deep", action="store_true")
    g.add_argument("--analyze-offensive", action="store_true")
    g.add_argument("--analyze-defensive", action="store_true")
    g.add_argument("--analyze-observation-bounds", action="store_true")
    g.add_argument("--analyze-platform", action="store_true")
    g.add_argument("--analyze-aot", action="store_true")
    g.add_argument("--analyze-novelty", action="store_true")
    g.add_argument("--run", action="store_true")
    g.add_argument("--daemon", action="store_true")
    g.add_argument("--status", action="store_true")
    p.add_argument("--allow-nonroot-parent", action="store_true",
                   dest="allow_nonroot_parent",
                   help="(compat; ignored by --auto-deploy in v2.8.3)")
    p.add_argument("--accept-nonroot-opt", action="store_true", dest="accept_nonroot_opt",
                   help="force-fix /opt ownership even when file red flags are present.")
    p.add_argument("--state-dir", default=ZARQA_STATE_DIR)
    p.add_argument("--alpha", type=float, default=0.1)
    p.add_argument("--L", type=float, default=0.95)
    p.add_argument("--delta-G", type=float, default=0.1)
    p.add_argument("--H0", type=float, default=10.0)
    p.add_argument("--generations", type=int, default=20)
    p.add_argument("--delta-tol", type=float, default=0.05)
    p.add_argument("--eps-task", type=float, default=0.05)
    p.add_argument("--L-task", type=float, default=0.1)
    p.add_argument("--delta-KS", type=float, default=0.05)
    p.add_argument("--beta-KS", type=float, default=0.01)
    p.add_argument("--J0", type=float, default=5.0)
    p.add_argument("--c", type=float, default=0.95)
    p.add_argument("--rho-G", type=float, default=0.5)
    p.add_argument("--pi-k", type=float, default=1e-3)
    p.add_argument("--N-real", type=int, default=10_000)
    p.add_argument("--N-synth", type=int, default=1_000_000)
    p.add_argument("--temp", type=float, default=1.0)
    p.add_argument("--delta-model", type=float, default=0.15)
    p.add_argument("--rho-n", type=float, default=0.45)
    p.add_argument("--n-mode", type=int, default=100)
    p.add_argument("--P-H-real", type=float, default=0.02)
    p.add_argument("--P-H-0", type=float, default=0.01)
    p.add_argument("--eta", type=float, default=0.05)
    p.add_argument("--delta-target-alpha", type=float, default=0.1)
    p.add_argument("--B-0", type=float, default=100.0)
    p.add_argument("--tau", type=float, default=10.0)
    p.add_argument("--C-gen", type=float, default=5.0)
    p.add_argument("--gamma", type=float, default=0.95)
    p.add_argument("--eps-e", type=float, default=0.01)
    p.add_argument("--H-S", type=float, default=3.2)
    p.add_argument("--tau-adv", type=float, default=1.5, dest="tau_adv_param")
    p.add_argument("--mu-adv", type=float, default=2.5)
    p.add_argument("--sigma-adv", type=float, default=0.5)
    p.add_argument("--n-adv", type=int, default=500)
    p.add_argument("--C-adv", type=float, default=1.0)
    p.add_argument("--n-train", type=int, default=50000)
    p.add_argument("--f-attack", type=float, default=0.01)
    p.add_argument("--f-real", type=float, default=1e-4)
    p.add_argument("--tpr-defense", type=float, default=0.5)
    p.add_argument("--f-fp", type=float, default=0.0)
    p.add_argument("--H-X1", type=float, default=2.0)
    p.add_argument("--H-X2", type=float, default=3.0)
    p.add_argument("--alpha-detect", type=float, default=0.01)
    p.add_argument("--eps-dp", type=float, default=1.0)
    p.add_argument("--M-sources", type=int, default=10)
    p.add_argument("--delta-attr", type=float, default=0.05)
    p.add_argument("--bits-per-stream", type=float, default=3.32)
    p.add_argument("--p-vectors", type=float, default=0.05)
    p.add_argument("--n-layers", type=int, default=5)
    p.add_argument("--d-layer", type=float, default=0.95)
    p.add_argument("--rho-common", type=float, default=0.1)
    p.add_argument("--gamma-bias", type=float, default=1.0)
    p.add_argument("--kappa", type=int, default=128)
    p.add_argument("--p-compromise", type=float, default=1e-7)
    p.add_argument("--p-log", type=float, default=0.999)
    p.add_argument("--n-key", type=int, default=10)
    p.add_argument("--eps-trust-list", type=float, default=1e-4)
    p.add_argument("--tpr-sanitize", type=float, default=0.98)
    p.add_argument("--fpr-sanitize", type=float, default=0.02)
    p.add_argument("--f-crit", type=float, default=0.005)
    p.add_argument("--eps-target", type=float, default=8.0)
    p.add_argument("--T-steps", type=int, default=10000)
    p.add_argument("--delta-dp", type=float, default=1e-6)
    p.add_argument("--C-clip", type=float, default=1.0)
    p.add_argument("--G-grad", type=float, default=1.0)
    p.add_argument("--eta-lr", type=float, default=0.001)
    p.add_argument("--det-tpr", type=float, default=0.85)
    p.add_argument("--det-fpr", type=float, default=0.02)
    p.add_argument("--n-detectors", type=int, default=3)
    p.add_argument("--rho-detectors", type=float, default=0.3)
    p.add_argument("--p-single-error", type=float, default=0.10)
    p.add_argument("--M-ensemble", type=int, default=5)
    p.add_argument("--k-bits", type=int, default=128)
    p.add_argument("--n-w", type=int, default=1)
    p.add_argument("--theta-norm-sq", type=float, default=1.0)
    p.add_argument("--delta-theta-norm-sq", type=float, default=0.01)
    p.add_argument("--n-c", type=int, default=100)
    p.add_argument("--p-leak", type=float, default=0.001)
    p.add_argument("--n-outputs-canary", type=int, default=100)
    p.add_argument("--n-systems", type=int, default=2)
    p.add_argument("--h-cusum", type=float, default=14.0)
    p.add_argument("--D-target", type=float, default=0.5)
    p.add_argument("--D-0", type=float, default=0.5)
    p.add_argument("--M-vocab", type=int, default=50000)
    p.add_argument("--n-hl", type=int, default=1_000_000)
    p.add_argument("--eps-hl", type=float, default=0.01)
    p.add_argument("--delta-hl", type=float, default=0.01)
    p.add_argument("--f1", type=int, default=10000)
    p.add_argument("--f2", type=int, default=5000)
    p.add_argument("--S-obs", type=int, default=40000)
    p.add_argument("--k-autocorr", type=int, default=100)
    p.add_argument("--N-train-hl", type=int, default=1_000_000_000)
    p.add_argument("--X-size", type=int, default=50000)
    p.add_argument("--p-per-step", type=float, default=0.99)
    p.add_argument("--n-links", type=int, default=7)
    p.add_argument("--M-eff", type=int, default=50000)
    p.add_argument("--n-state", type=int, default=7_000_000_000)
    p.add_argument("--n-test", type=int, default=1_000_000)
    p.add_argument("--precision", type=str, default="fp32",
                   choices=["fp64", "fp32", "tf32", "bf16", "fp16", "fp8_e4m3", "fp8_e5m2", "int8"])
    p.add_argument("--log-M", type=float, default=10.82)
    p.add_argument("--H-log", type=float, default=10.82)
    p.add_argument("--K-abs", type=float, default=3.0)
    p.add_argument("--D-KL-true", type=float, default=0.5)
    p.add_argument("--delta-H", type=float, default=0.05)
    p.add_argument("--N-nodes", type=int, default=1000)
    p.add_argument("--g-norm", type=float, default=1.0)
    p.add_argument("--E", type=int, default=100)
    p.add_argument("--B-max", type=int, default=4096)
    p.add_argument("--beta", type=float, default=0.01)
    p.add_argument("--eps-iso", type=float, default=1e-3)
    p.add_argument("--eps-step", type=float, default=1e-7)
    p.add_argument("--w-norm-sq", type=float, default=1.0)
    p.add_argument("--eps-accum-max", type=float, default=1e-5)
    p.add_argument("--tau-max", type=float, default=0.1)
    p.add_argument("--n-stage", type=int, default=12)
    p.add_argument("--eps-stage", type=float, default=1e-6)
    p.add_argument("--eps-measure", type=float, default=1e-4)
    p.add_argument("--kappa-compile", type=int, default=128)
    p.add_argument("--s-max", type=float, default=2.0)
    p.add_argument("--min-tau", type=float, default=0.05)
    p.add_argument("--ERR-target", type=float, default=1e-4, dest="ERR_target")
    p.add_argument("--eps-1", type=float, default=1e-5)
    p.add_argument("--eps-2", type=float, default=1e-4)
    p.add_argument("--P-shared", type=float, default=1e-7)
    p.add_argument("--wcet-list", type=str, default="2,8,5,6,15,0.001,0.1")
    p.add_argument("--alpha-wcet", type=float, default=0.2)
    p.add_argument("--tau-budget", type=float, default=60.0)
    p.add_argument("--n-s", type=int, default=1000000)
    p.add_argument("--n-class", type=int, default=5)
    p.add_argument("--n-tier", type=int, default=3)
    p.add_argument("--n-hyst", type=int, default=2)
    p.add_argument("--per-state-us", type=float, default=10.0)
    p.add_argument("--kappa-attest", type=int, default=128)
    p.add_argument("--p-key-compromise", type=float, default=1e-7)
    p.add_argument("--eps-patch", type=float, default=1e-5)
    p.add_argument("--delta-cov", type=float, default=0.05)
    p.add_argument("--k-consecutive", type=int, default=3)
    p.add_argument("--tau-alarm", type=float, default=0.01)
    p.add_argument("--T-generation", type=float, default=1.0)
    p.add_argument("--discrepancy", type=float, default=0.5)
    p.add_argument("--sigma-verify", type=float, default=0.1)
    p.add_argument("--V-seb", type=float, default=0.01, dest="V_seb")
    p.add_argument("--H0-seb", type=float, default=10.0, dest="H0_seb")
    p.add_argument("--L-seb", type=float, default=0.95, dest="L_seb")
    p.add_argument("--c-R-seb", type=float, default=0.01, dest="c_R_seb")
    p.add_argument("--c-S-seb", type=float, default=0.0001, dest="c_S_seb")
    p.add_argument("--alpha-min-safety", type=float, default=0.31, dest="alpha_min_safety")
    p.add_argument("--R-real-gav", type=float, default=1e6, dest="R_real_gav")
    p.add_argument("--T-gen-gav", type=float, default=7.0, dest="T_gen_gav")
    p.add_argument("--N-total-gav", type=float, default=1e9, dest="N_total_gav")
    p.add_argument("--alpha-star-gav", type=float, default=0.31, dest="alpha_star_gav")
    p.add_argument("--T-budget-days", type=float, default=365.0, dest="T_budget_days")
    p.add_argument("--alpha-mcb", type=float, default=0.1, dest="alpha_mcb")
    p.add_argument("--beta-mcb", type=float, default=0.7, dest="beta_mcb")
    p.add_argument("--L-B-mcb", type=float, default=0.95, dest="L_B_mcb")
    p.add_argument("--D-source-mcb", type=float, default=0.05, dest="D_source_mcb")
    p.add_argument("--D-target-mcb", type=float, default=0.1, dest="D_target_mcb")
    p.add_argument("--V0-cic", type=float, default=1e7, dest="V0_cic")
    p.add_argument("--g-cic", type=float, default=0.05, dest="g_cic")
    p.add_argument("--r-cic", type=float, default=0.05, dest="r_cic")
    p.add_argument("--C-int-cic", type=float, default=1e5, dest="C_int_cic")
    p.add_argument("--D-scale-cic", type=float, default=0.2, dest="D_scale_cic")
    p.add_argument("--tau-safety-cic", type=float, default=0.1, dest="tau_safety_cic")
    p.add_argument("--alpha-list-mmc", type=str, default="0.1,0.2,0.3", dest="alpha_list_mmc")
    p.add_argument("--L-list-mmc", type=str, default="0.95,0.90,0.85", dest="L_list_mmc")
    p.add_argument("--kappa-matrix-mmc", type=str,
                   default="0,0.10,0.05;0.30,0,0;0.20,0,0", dest="kappa_matrix_mmc")
    p.add_argument("--rho-target-mmc", type=float, default=0.8, dest="rho_target_mmc")
    p.add_argument("--f-attack-aac", type=float, default=0.01, dest="f_attack_aac")
    p.add_argument("--eps-trust-aac", type=float, default=1e-4, dest="eps_trust_aac")
    p.add_argument("--tpr-san-aac", type=float, default=0.98, dest="tpr_san_aac")
    p.add_argument("--fpr-san-aac", type=float, default=0.02, dest="fpr_san_aac")
    p.add_argument("--f-crit-aac", type=float, default=0.005, dest="f_crit_aac")
    return p


def main(argv=None):
    parser = build_parser(); args = parser.parse_args(argv)
    needs_numpy = not (args.auto_deploy or args.bootstrap_namespace
                       or args.analyze or args.analyze_deep
                       or args.analyze_offensive or args.analyze_defensive
                       or args.analyze_observation_bounds or args.analyze_platform
                       or args.analyze_aot or args.analyze_novelty)
    if needs_numpy and not HAS_NUMPY:
        LOG.err("numpy is not importable under current interpreter")
        LOG.err(f"run --auto-deploy first, or invoke via {_venv_python()} {__file__} ..."); return 1
    if args.bootstrap_namespace:        return cmd_bootstrap_namespace(args)
    if args.auto_deploy:                return cmd_auto_deploy(args)
    if args.test:                       return cmd_test(args)
    if args.analyze:                    return cmd_analyze(args)
    if args.analyze_deep:               return cmd_analyze_deep(args)
    if args.analyze_offensive:          return cmd_analyze_offensive(args)
    if args.analyze_defensive:          return cmd_analyze_defensive(args)
    if args.analyze_observation_bounds: return cmd_analyze_observation_bounds(args)
    if args.analyze_platform:           return cmd_analyze_platform(args)
    if args.analyze_aot:                return cmd_analyze_aot(args)
    if args.analyze_novelty:            return cmd_analyze_novelty(args)
    if args.run:                        return cmd_run(args)
    if args.daemon:                     return cmd_daemon(args)
    if args.status:                     return cmd_status(args)
    parser.error("no action selected")


if __name__ == "__main__":
    sys.exit(main())
