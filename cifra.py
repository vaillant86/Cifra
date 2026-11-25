#!/usr/bin/env python3
import sys
import os
import getpass
import struct
import tarfile
import argparse
import time
import fnmatch
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

__version__ = "1.4.0"

CHUNK_SIZE = 64 * 1024
MAGIC_HEADER = b'ENC2'

# Header format: 4B (magic) + 1B (is_dir) + 3x4B (n, r, p) + 16B (salt) + 12B (nonce)
HEADER_FORMAT = '>4sBIII16s12s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # Total: 45 bytes


class UserAborted(Exception):
    """Raised when the user declines an interactive confirmation."""
    pass


def log(message):
    """Writes all informational text to stderr so stdout is safe for binary pipes."""
    sys.stderr.write(message + '\n')
    sys.stderr.flush()


def get_key(pwd_bytes, salt, n, r, p):
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(pwd_bytes)


class ProgressBar:
    def __init__(self, bar_length=40, min_interval=0.15):
        self.bar_length = bar_length
        self.min_interval = min_interval
        self.last_update = 0.0

    def update(self, current, total):
        current_time = time.monotonic()
        if (
            total > 0
            and current < total
            and self.last_update > 0
            and (current_time - self.last_update) < self.min_interval
        ):
            return

        self.last_update = current_time

        if total == 0:
            mb = current / (1024 * 1024)
            sys.stderr.write(f'\rProgress: {mb:.2f} MB processed')
        else:
            percent = min(100.0, float(current) * 100 / total)
            arrow = '-' * int(percent / 100 * self.bar_length - 1) + '>'
            spaces = ' ' * (self.bar_length - len(arrow))
            sys.stderr.write(f'\rProgress: [{arrow}{spaces}] {percent:.2f}%')

        sys.stderr.flush()

        if total > 0 and current >= total:
            self.last_update = 0.0


def should_exclude(path, excludes):
    """Matches fnmatch patterns against both the basename and the relative path."""
    name = os.path.basename(path)
    for pattern in excludes:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
            return True
    return False


def get_target_size(path, excludes):
    if os.path.isfile(path) and not os.path.islink(path):
        return os.path.getsize(path)

    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if not should_exclude(os.path.join(dirpath, d), excludes)]
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not should_exclude(fp, excludes):
                total += os.lstat(fp).st_size
    return total


def same_file(a, b):
    """Checks if two paths refer to the exact same physical file (including symlinks and hard links)."""
    a = os.path.abspath(a)
    b = os.path.abspath(b)

    if os.path.realpath(a) == os.path.realpath(b):
        return True

    try:
        return os.path.samefile(a, b)
    except (FileNotFoundError, OSError):
        return False


def validate_output(out_path, target=None, force=False):
    """Validates output path against symlinks, parent symlinks, directories, source clobbering, and overwrites."""
    if not out_path:
        raise ValueError("No output path was specified.")

    if os.path.islink(out_path):
        raise ValueError(f"Refusing to write to symbolic link: '{out_path}'")

    out_path = os.path.abspath(out_path)

    if os.path.isdir(out_path):
        raise ValueError(f"'{out_path}' is a directory.")

    parent = os.path.dirname(out_path)
    if os.path.islink(parent):
        raise ValueError(f"Refusing to write inside symbolic link directory: '{parent}'")

    if not os.path.isdir(parent):
        raise ValueError(f"Output directory '{parent}' does not exist.")

    if target and same_file(out_path, target):
        raise ValueError("Output path refers to the source file.")

    if os.path.lexists(out_path) and not force:
        if not sys.stdin.isatty():
            raise FileExistsError(
                f"'{out_path}' exists. Use -f to overwrite in non-interactive mode."
            )

        ans = input(
            f"\nWarning: '{out_path}' already exists. Overwrite? [y/N]: "
        ).strip().lower()

        if ans not in ("y", "yes"):
            raise UserAborted("Operation aborted.")

    return out_path


def create_output_temp(out_path):
    """Creates an atomic temporary file in the destination directory with 0600 permissions."""
    parent = os.path.dirname(out_path) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(out_path)}.",
        suffix=".tmp",
        dir=parent,
    )
    try:
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "wb"), tmp_path
    except Exception:
        os.close(fd)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


class EncryptingStream:
    def __init__(self, out_f, encryptor, total_size, progress):
        self.out_f = out_f
        self.encryptor = encryptor
        self.total_size = total_size
        self.progress = progress
        self.written = 0

    def write(self, data):
        encrypted = self.encryptor.update(data)
        self.out_f.write(encrypted)
        self.written += len(data)
        self.progress.update(self.written, self.total_size)
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass


def get_password_bytes(keyfile, is_confirm_needed=False):
    if keyfile:
        if not os.path.isfile(keyfile):
            raise FileNotFoundError(f"Keyfile '{keyfile}' does not exist.")
        try:
            with open(keyfile, 'rb') as kf:
                pwd_bytes = kf.read(4 * 1024 * 1024)
                if not pwd_bytes:
                    raise ValueError("Keyfile is empty.")
                return pwd_bytes
        except (ValueError, FileNotFoundError):
            raise
        except Exception as e:
            raise IOError(f"Error reading keyfile: {e}") from e
    else:
        prompt = "Enter password to encrypt: " if is_confirm_needed else "Enter password to decrypt: "
        pwd1 = getpass.getpass(prompt)
        if not pwd1:
            raise ValueError("Password cannot be empty.")

        if is_confirm_needed:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd1 != pwd2:
                raise ValueError("Passwords do not match.")

        return pwd1.encode('utf-8')


def encrypt_target(target, is_stream, out_path, force, keyfile, excludes, progress):
    if is_stream:
        is_dir = False
        total_size = 0
        tmp_path = None
        if out_path:
            out_path = validate_output(out_path, target=None, force=force)
            f_out, tmp_path = create_output_temp(out_path)
        else:
            f_out = sys.stdout.buffer
    else:
        is_dir = os.path.isdir(target)
        raw_out = out_path or (target + ".enc")
        out_path = validate_output(raw_out, target=target, force=force)
        total_size = get_target_size(target, excludes)
        f_out, tmp_path = create_output_temp(out_path)

    try:
        pwd_bytes = get_password_bytes(keyfile, is_confirm_needed=True)
    except Exception:
        if f_out is not sys.stdout.buffer and not f_out.closed:
            f_out.close()
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    scrypt_n, scrypt_r, scrypt_p = 131072, 8, 1
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = get_key(pwd_bytes, salt, scrypt_n, scrypt_r, scrypt_p)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    try:
        header = struct.pack(HEADER_FORMAT, MAGIC_HEADER, 1 if is_dir else 0, scrypt_n, scrypt_r, scrypt_p, salt, nonce)
        encryptor.authenticate_additional_data(header)
        f_out.write(header)

        if not is_stream and is_dir:
            stream = EncryptingStream(f_out, encryptor, total_size, progress)

            def tar_filter(tarinfo):
                if should_exclude(tarinfo.name, excludes):
                    return None
                return tarinfo

            with tarfile.open(fileobj=stream, mode='w|') as tar:
                tar.add(target, arcname=os.path.basename(target), filter=tar_filter)
        else:
            processed = 0
            f_in = sys.stdin.buffer if is_stream else open(target, 'rb')
            try:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))
                    processed += len(chunk)
                    progress.update(processed, total_size)
            finally:
                if not is_stream:
                    f_in.close()

        sys.stderr.write('\n')
        encryptor.finalize()
        f_out.write(encryptor.tag)

        if f_out is not sys.stdout.buffer:
            f_out.close()

        if tmp_path:
            os.replace(tmp_path, out_path)
            log(f"Encryption completed. File created: '{out_path}'")

    except (Exception, KeyboardInterrupt) as e:
        if f_out is not sys.stdout.buffer and not f_out.closed:
            f_out.close()
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise RuntimeError(f"Encryption aborted: {e}") from e


def decrypt_target(target, is_stream, out_path, force, keyfile, progress):
    spool_file_path = None

    if is_stream:
        fd, spool_file_path = tempfile.mkstemp(prefix=".cifra_spool_")
        try:
            os.fchmod(fd, 0o600)
            spool_f = os.fdopen(fd, 'wb')
        except Exception:
            os.close(fd)
            if os.path.exists(spool_file_path):
                os.remove(spool_file_path)
            raise

        sys.stderr.write("Spooling stdin stream to temporary file for GCM tag verification...\n")
        try:
            while True:
                chunk = sys.stdin.buffer.read(CHUNK_SIZE)
                if not chunk:
                    break
                spool_f.write(chunk)
        finally:
            spool_f.close()
        target_path = spool_file_path
    else:
        target_path = target
        if not os.path.isfile(target_path):
            raise ValueError(f"Target '{target_path}' must be a file.")

    try:
        file_size = os.path.getsize(target_path)
        if file_size < HEADER_SIZE + 16:
            raise ValueError("File is too small to contain valid encrypted data.")

        with open(target_path, 'rb') as f_in:
            header_data = f_in.read(HEADER_SIZE)
            magic, flag_is_dir, n, r, p, salt, nonce = struct.unpack(HEADER_FORMAT, header_data)

            if magic == b'ENC1':
                raise ValueError("File created with an older version. Use the previous script.")
            elif magic != MAGIC_HEADER:
                raise ValueError("Invalid signature. The file was not encrypted with this program.")

            if not (n > 0 and (n & (n - 1)) == 0) or not (16384 <= n <= 1048576) or not (1 <= r <= 16) or not (1 <= p <= 4):
                raise ValueError("Scrypt parameters out of bounds (corrupted or tampered).")

        tmp_path = None

        if is_stream and not out_path:
            f_out = sys.stdout.buffer
        else:
            if not out_path:
                if target.endswith('.enc'):
                    base_out = target[:-4]
                else:
                    base_out = target + ".dec"
                raw_out = base_out + (".tar" if flag_is_dir == 1 and not base_out.endswith(".tar") else "")
            else:
                raw_out = out_path

            out_path = validate_output(raw_out, target=(None if is_stream else target_path), force=force)
            f_out, tmp_path = create_output_temp(out_path)

        try:
            pwd_bytes = get_password_bytes(keyfile, is_confirm_needed=False)
        except Exception:
            if f_out is not sys.stdout.buffer and not f_out.closed:
                f_out.close()
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        try:
            with open(target_path, 'rb') as f_in:
                f_in.seek(-16, os.SEEK_END)
                tag = f_in.read(16)

                f_in.seek(HEADER_SIZE)

                key = get_key(pwd_bytes, salt, n, r, p)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decryptor.authenticate_additional_data(header_data)

                total_data = file_size - HEADER_SIZE - 16
                bytes_left = total_data
                processed = 0

                while bytes_left > 0:
                    chunk_size = min(CHUNK_SIZE, bytes_left)
                    chunk = f_in.read(chunk_size)
                    f_out.write(decryptor.update(chunk))
                    processed += len(chunk)
                    bytes_left -= len(chunk)
                    progress.update(processed, total_data)

                sys.stderr.write('\n')
                decryptor.finalize()

            if f_out is not sys.stdout.buffer:
                f_out.close()

            if tmp_path:
                os.replace(tmp_path, out_path)
                log(f"Decryption completed. Restored: '{out_path}'")
                if flag_is_dir == 1:
                    log(f"Note: the original target was a directory. It has been restored as archive '{out_path}'.")

        except InvalidTag as e:
            if f_out is not sys.stdout.buffer and not f_out.closed:
                f_out.close()
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise PermissionError("Access denied: incorrect password/keyfile, or tampered file (Header/Data corrupted).") from e
        except (Exception, KeyboardInterrupt) as e:
            if f_out is not sys.stdout.buffer and not f_out.closed:
                f_out.close()
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise RuntimeError(f"Decryption aborted: {e}") from e
    finally:
        if spool_file_path and os.path.exists(spool_file_path):
            os.remove(spool_file_path)


def main():
    parser = argparse.ArgumentParser(description="Cifra - encryption tool for files and directories.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform (encrypt or decrypt)")
    parser.add_argument("target", help="Target file, directory, or '-' for standard input/output")
    parser.add_argument("-o", "--output", type=str, help="Specify explicit output file (defaults to <target>.enc or stdout if '-')")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing files without asking")
    parser.add_argument("-k", "--keyfile", type=str, help="Use a file as key instead of a text password")
    parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=[],
        help="Exclude files/directories matching fnmatch glob pattern against basename or relative path (e.g. '*.log', 'dir/cache')",
    )
    args = parser.parse_args()

    is_stream = (args.target == '-')
    progress = ProgressBar()

    try:
        if not is_stream:
            target = os.path.normpath(args.target)
            if not os.path.exists(target):
                raise FileNotFoundError(f"Target '{target}' does not exist.")
        else:
            target = args.target

        if args.action == "encrypt":
            encrypt_target(target, is_stream, args.output, args.force, args.keyfile, args.exclude, progress)
        elif args.action == "decrypt":
            decrypt_target(target, is_stream, args.output, args.force, args.keyfile, progress)

    except UserAborted as e:
        log(str(e))
        sys.exit(0)
    except KeyboardInterrupt:
        log("\nOperation interrupted by user.")
        sys.exit(130)
    except Exception as e:
        log(f"\nError: {e}" if str(e).startswith("Access denied") else f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()