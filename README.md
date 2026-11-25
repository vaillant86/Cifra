# Cifra

A command-line tool to encrypt and decrypt files and directories with **AES-256-GCM**, using a key derived with **scrypt** from a password or a keyfile.

Single Python file, one dependency, works on Linux, macOS, and Windows with Python 3.8+.

## Features

- **Strong authenticated encryption**: AES-256-GCM, so any wrong password or modified file is detected on decryption. The entire file header (`CFRA` v1, with backward read support for legacy `ENC2` files) is also protected via Additional Authenticated Data (AAD).
- **Memory-hard key derivation**: scrypt (`n=2^17`, `r=8`, `p=1`, about 128 MiB of RAM) with a random 16-byte salt for every file.
- **Files and directories**: a directory is archived with `tar` on the fly and encrypted in a single stream (symbolic links and special files inside directories are safely skipped).
- **Streaming & Pipes**: data is processed in 64 KB chunks. Use `-` as the target to encrypt/decrypt data streams directly via Unix pipes without touching the disk.
- **File exclusion**: ignore specific files or directories during archiving using standard wildcard patterns (`-e`).
- **Password or keyfile**: type a password (asked twice when encrypting) or use any file as a key with `-k`.
- **Safe writes**: output goes to an atomic temporary file (`0600` permissions via `fchmod`) in the destination directory and replaces the target only after the operation succeeds. On errors or `Ctrl-C` the temporary file is removed.
- **Overwrite, hardlink & symlink protection**: asks before replacing an existing file (unless `-f` is given), prevents overwriting the source file or its hard links, and refuses to write to symbolic links or inside any symlinked ancestor directory.
- **Hardened decryption**: scrypt parameters read from the file are validated (`n` a power of two between 2^14 and 2^20, `r` 1-16, `p` 1-4) before any memory is allocated, so a crafted file cannot exhaust your RAM.
- **Performance optimized**: smart I/O throttling on the progress bar maximizes NVMe disk speeds without terminal lag.

## Requirements

- Python 3.8 or newer
- The [`cryptography`](https://pypi.org/project/cryptography/) package (`>= 41.0.0`)

On Debian, Ubuntu or Linux Mint:

```bash
sudo apt install python3-cryptography
```

On Fedora, RHEL, or CentOS:

```bash
sudo dnf install python3-cryptography
```

On Arch Linux or Manjaro:

```bash
sudo pacman -S python-cryptography
```

Or via `pip`:

```bash
pip install "cryptography>=41.0.0"
```

## Installation (Linux / macOS)

```bash
chmod +x cifra.py
sudo cp cifra.py /usr/local/bin/cifra
```

## Usage

```
cifra [-h] [-v] [-f] [-o OUTPUT] [-k KEYFILE] [-e PATTERN] {encrypt,decrypt} target
```

| Argument | Description |
|----------|-------------|
| `encrypt` | Encrypt `target` and create `<target>.enc` |
| `decrypt` | Decrypt `target` (a `.enc` file created by this tool) |
| `target` | File or directory to process, or `-` for standard input/output |
| `-o`, `--output` | Specify an explicit output file path |
| `-f`, `--force` | Overwrite existing output files without asking |
| `-k`, `--keyfile` | Use the contents of a file as the key instead of a password |
| `-e`, `--exclude` | Exclude files/directories matching `fnmatch` pattern against basename or relative path (e.g. `*.log`) |
| `-v`, `--version` | Show program's version number and exit |

Notes about keyfiles:

- The keyfile is read directly as raw key material (up to 4 MB) and passed straight to `scrypt` without pre-hashing; an empty keyfile is rejected.
- Use a binary file, not a text file: if an editor changes even one byte (for example by adding a trailing newline), the key changes and you will not be able to decrypt.
- Keep a backup copy. Without the keyfile the data cannot be recovered.

## Examples

### Basic encryption and decryption

```bash
# Encrypt a single file (creates foo.bar.enc)
cifra encrypt foo.bar

# Decrypt the file back to its original name
cifra decrypt foo.bar.enc

# Specify a custom output path and overwrite without asking
cifra encrypt -f -o /mnt/backup/archive.enc /var/www/html
```

### Exclude files when encrypting a directory

```bash
cifra encrypt --exclude "*.log" --exclude "html/cache/*" /var/www/html
```

Patterns use `fnmatch` glob syntax and are matched against both the file/directory basename (e.g. `*.log`, `node_modules`) and its relative archive path (e.g. `html/cache/*`).

### Use a keyfile instead of a password

```bash
cifra encrypt -k my.key foo.bar
cifra decrypt -k my.key foo.bar.enc
```

### Stream via Unix pipes (no intermediate files on disk)

```bash
# Compress and encrypt a directory on the fly
tar -czf - /var/log/apache2 | cifra encrypt -k my.key - > logs.tar.gz.enc

# Decrypt from a stream and extract immediately
cifra decrypt -k my.key - < logs.tar.gz.enc | tar -xzf -
```

### Run without installing

```bash
python3 cifra.py encrypt foo.bar
python3 cifra.py decrypt foo.bar.enc
```

## Running Tests

```bash
python3 -m unittest discover -v
```

## Limitations and security notes

- This is a personal tool and has **not** been independently audited. For critical data, prefer a well-established tool.
- The original file or directory is **not deleted** after encryption. Remove it yourself if you need to. Note that secure deletion is not reliable on SSDs and copy-on-write filesystems; full-disk encryption is the better protection there.
- A temporary `.tmp` file is written next to the output while the operation runs (unless streaming via pipes).
- Losing the password or the keyfile means losing the data: there is no recovery.
- AES-GCM with a single nonce is limited to about 64 GiB per file.
- With `-k` the keyfile alone is the secret. Anyone who holds that file can decrypt your data.
- Directories are restored as `.tar` archives rather than extracted automatically. As with any tar file, only extract archives you trust.
- Python strings and byte buffers are immutable and cannot be deterministically zeroed in memory after use.
- Symbolic links and special files (FIFOs, sockets, device nodes) are skipped when archiving directories.

## License

This project is licensed under the GNU AGPLv3 License - see the [LICENSE](LICENSE) file for details.