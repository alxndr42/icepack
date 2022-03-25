# icepack Format Specification

Version 1.0.0

## Overview

icepack combines [age encryption][], [SSH signatures][] and ZIP files to create
encrypted and verifiable archives. Except for the number of files and their
approximate size, no metadata is visible.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119][].

[age encryption]: https://age-encryption.org/
[rfc 2119]: https://datatracker.ietf.org/doc/html/rfc2119
[ssh signatures]: https://www.agwa.name/blog/post/ssh_signatures

## ZIP File

The ZIP file serves purely as an archive for storing previously compressed and
encrypted files. Metadata for archived files and directories is stored in the
ZIP file as a compressed and encrypted JSON file. ZIP64 extensions MUST be
supported.

Listing of an example archive:

```
$ unzip -v foo.zip
Archive:  foo.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
     240  Stored      240   0% 1980-01-01 00:00 2cf5132d  00000001
     240  Stored      240   0% 1980-01-01 00:00 52d09c57  00000002
     620  Stored      620   0% 1980-01-01 00:00 aeba16e6  metadata.gz.age
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgpfeNpjaM+syMGnLsxEKOQTaMJW
vGYQy3fpOOorF2+l4AAAAHaWNlcGFjawAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQy
NTUxOQAAAEAOQJ6Sw139NKHifS0ecsNVBte8kekCAJSiVcDt2mnav0zTj9USWolUCb6nk+
7vuQayY+EMAg16z4Cyksdy+20J
-----END SSH SIGNATURE-----
--------          -------  ---                            -------
    1100             1100   0%                            3 files
```

Requirements for all ZIP entries:

- The name MUST be unique.
- The compression method MUST be `Stored`.
- The modification date fields SHOULD be all zeroes (`1980-01-01`).

Requirements for all ZIP entries before the last:

- The name MUST NOT start with `metadata`.
- The name SHOULD NOT reveal information about the original filename.

Requirements for the last ZIP entry:

- The entry MUST contain the compressed and encrypted metadata file.
- The name MUST match the pattern `metadata.CT.ET`, where `CT` is the
  [compression](#compression) type and `ET` the [encryption](#encryption) type.
- The entry MUST have a comment containing the [signature](#signing) of the
  compressed and encrypted metadata file.

## Metadata

Except for the number and approximate size of archived files, all information
in the ZIP file directory SHOULD be nondescript. Actual archive metadata is
stored in a compressed and encrypted JSON file at the end of the archive.

Metadata of an example archive:

```json
{
  "archive_name": "foo.zip",
  "comment": "foo",
  "checksum_type": "sha256",
  "encryption": "age",
  "encryption_key": "SYMMETRIC-ENCRYPTION-KEY-FOR-FILES",
  "entries": [
    {
      "entry_type": "dir",
      "name": "foo",
      "mode": 493,
      "mtime": 1647805849266461200
    },
    {
      "entry_type": "file",
      "name": "foo/bar",
      "size": 4,
      "mode": 384,
      "mtime": 1647805819754307800,
      "compression": "gz",
      "stored_name": "00000001",
      "stored_size": 240,
      "stored_checksum": "c08379282894c5730aaef42a9035da585bb24da91a176ba8cb0cf80e09b762dc"
    },
    {
      "entry_type": "file",
      "name": "foo/baz",
      "size": 4,
      "mode": 493,
      "mtime": 1647805849254461200,
      "compression": "gz",
      "stored_name": "00000002",
      "stored_size": 240,
      "stored_checksum": "454838fc3d337d8f09a1bb4b8184bd19635bd1ca888a274b1dfc46ef7ada9f20"
    }
  ]
}
```

Values are strings, unless noted otherwise.

### Top-level Attributes

| Name | Required | Description |
| --- | --- | --- |
| `archive_name` | Yes | SHOULD contain the original filename of the archive. |
| `comment` | No | Descriptive comment for the archive. |
| `checksum_type` | Yes | [Checksum](#checksums) type for file entries. |
| `encryption` | Yes | [Encryption](#encryption) type for file entries. |
| `encryption_key` | Yes | Symmetric file encryption key used by `encryption`. |
| `entries` | Yes | List of file or directory entries. |

### File Entry Attributes

| Name | Required | Description |
| --- | --- | --- |
| `entry_type` | Yes | MUST be `file`. |
| `name` | Yes | Relative path of the file in the archive, ending in the filename. |
| `size` | Yes | Original size of the file. (Type: int) |
| `mode` | No | File mode bits. (Type: int) |
| `mtime` | No | File modification timestamp as nanoseconds. (Type: int) |
| `compression` | Yes | [Compression](#compression) type used for the file. |
| `stored_name` | Yes | Name of the ZIP entry for the file. |
| `stored_size` | Yes | Size of the ZIP entry for the file. |
| `stored_checksum` | Yes | Checksum value of the ZIP entry for the file. |

### Directory Entry Attributes

| Name | Required | Description |
| --- | --- | --- |
| `entry_type` | Yes | MUST be `dir`. |
| `name` | Yes | Relative path of the directory in the archive, ending in the directory name. |
| `mode` | No | Directory mode bits. (Type: int) |
| `mtime` | No | Directory modification timestamp as nanoseconds. (Type: int) |

## Checksums

The `checksum_type` attribute defines how to create and verify checksum values
in `stored_checksum`. The checksum MUST be calculated after compressing and
encrypting the original file and verified before decrypting and uncompressing
the ZIP entry.

Supported checksum types:

| Name | Description |
| --- | --- |
| `sha256` | Lower case hex string as produced by `sha256sum`. |

## Compression

The `compression` attribute defines the compression type used for a file entry.
The original file MUST be compressed before encryption.

The compression type for the metadata file MUST be `gz`.

Supported compression types:

| Name | Description |
| --- | --- |
| `bz2` | Compressed file as produced/consumed by `bzip2`/`bunzip2`. |
| `gz` | Compressed file as produced/consumed by `gzip`/`gunzip`. |
| `none` | Uncompressed file. |

## Encryption

The `encryption` attribute defines the encryption type used for file entries.
The `encryption_key` attribute MUST contain the symmetric key used for
encrypting file entries. File entries MUST be encrypted after compression.

The key pair used for encrypting and signing the metadata file MUST be distinct
from the `encryption_key`.

Supported encryption types:

| Name | Description |
| --- | --- |
| `age` | Encrypted file as produced/consumed by `age`. |

## Signing

The ZIP entry for the metadata file MUST have a comment containing the
signature of the metadata file as created by `ssh-keygen -Y sign`. The key pair
used for signing MUST be the key pair used for encrypting the metadata file.

The signature of the metadata file MUST be verified before decrypting and
uncompressing the metadata file.

## History

- 2022-03-25: Version 1.0.0
