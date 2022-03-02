# icepack - Encrypting File Archiver

icepack combines [age encryption][], [SSH signatures][] and Zip files to create
encrypted and verifiable archives. Except for the number of files and their
approximate size, no metadata is visible.

[age encryption]: https://age-encryption.org/
[ssh signatures]: https://www.agwa.name/blog/post/ssh_signatures

## Installation

Requirements:

- Python 3.8
- age 1.0
- OpenSSH 8.0

Install with `pip` or [pipx][]:

```
$ pip install icepack
```

[pipx]: https://pypa.github.io/pipx/

## Basic Usage

### Initialize the keys

```
$ icepack init
Enter passphrase (empty for no passphrase): *****
Enter same passphrase again: *****
The keys have been initialized in /home/username/.config/icepack
Make sure to protect and backup this directory!
```

### Create an archive

```
$ icepack create $HOME/Documents/ $HOME/my-documents.zip
Documents/Cat Pictures
Documents/Cat Pictures/awww.jpg
Documents/Cat Pictures/grumpy.jpg
Documents/Cat Pictures/socute.jpg
Documents/world-domination.txt
Enter passphrase: *****
```

| Option | Description |
| --- | --- |
| `--comment` | Archive comment. |
| `--compression`, `-c` | Compression for all files: `bz2`, `gz` or `none` (Default: `gz`) |
| `--mode` | Store file/directory modes. |
| `--mtime` | Store file/directory modification times. |
| `--recipient`, `-r` | Allow another public key/alias to extract. |

### Extract an archive

```
$ icepack extract $HOME/my-documents.zip $HOME/
Enter passphrase for "/home/username/.config/icepack/identity": *****
Documents/Cat Pictures
Documents/Cat Pictures/awww.jpg
Documents/Cat Pictures/grumpy.jpg
Documents/Cat Pictures/socute.jpg
Documents/world-domination.txt
```

| Option | Description |
| --- | --- |
| `--mode` | Restore file/directory modes. |
| `--mtime` | Restore file/directory modification times. |

### Check the version and dependencies

```
$ icepack version --dependencies
icepack 0.1.0
✅ age found. (Version: v1.0.0)
✅ age-keygen found.
✅ ssh found. (Version: OpenSSH_8.2p1)
✅ ssh-keygen found.
```

| Option | Description |
| --- | --- |
| `--dependencies`, `-d` | Check the dependencies. |

## Signer Management

To extract archives created by other parties, their public keys need to be
added to the list of allowed signers. The `signer` command supports this.

### List allowed signers

```
$ icepack signer list
ssh-ed25519 AAAAC3NzaC... (Your Key)
ssh-ed25519 AAAAC3NzaC... (Bob)
```

### Add an allowed signer

```
$ icepack signer add "ssh-ed25519 AAAAC3NzaC..." --alias Alice
$ icepack signer list
ssh-ed25519 AAAAC3NzaC... (Your Key)
ssh-ed25519 AAAAC3NzaC... (Bob)
ssh-ed25519 AAAAC3NzaC... (Alice)
```

| Option | Description |
| --- | --- |
| `--alias`, `-a` | Key alias. |

### Remove an allowed signer

```
$ icepack signer remove Bob
$ icepack signer list
ssh-ed25519 AAAAC3NzaC... (Your Key)
ssh-ed25519 AAAAC3NzaC... (Alice)
```

When removing a key, you can specify the key or its alias.
