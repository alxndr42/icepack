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

## Usage

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

You can allow additional recipients to extract the archive by passing their
public keys via the `--recipient` option.

### Extract an archive

```
$ icepack extract $HOME/my-documents.zip $HOME/
Enter passphrase for "/home/username/.config/icepack/identity": *****
Documents/Cat Pictures/
Documents/Cat Pictures/awww.jpg
Documents/Cat Pictures/grumpy.jpg
Documents/Cat Pictures/socute.jpg
Documents/world-domination.txt
```

### Check the version and dependencies

```
$ icepack version --dependencies
icepack 0.1.0
✅ age found. (Version: v1.0.0)
✅ age-keygen found.
✅ ssh found. (Version: OpenSSH_8.2p1)
✅ ssh-keygen found.
```
