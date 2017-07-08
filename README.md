# xor

Command line application that implements basic XOR encryption, written in Rust.

Can XOR encrypt from stdin, a file, or recursively encrypting all contents of a directory (including renaming files).

## Installation

If you've not already done so, install rust:
https://www.rust-lang.org/

Then install via cargo with:
```bash
$ cargo install xor
```

## Help
```bash
$ xor --help
xor 1.4.0
Gavyn Riebau

XOR encrypt files or directories using a supplied key.

In it's simplest form, reads input from stdin, encrypts it against a key and writes the result to stdout.
The "key" option can be either a path to a file or a string of characters.

When the "recursive" option is used, files under a given directory are recursively encrypted.
Files are renamed by XORing the original name against the provided key, then hexifying the result.
To decrypt you must use the "mode" option with the value "d", files are then renamed by unhexifying then XORing.

USAGE:
    xor [OPTIONS] --key <KEY>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --input <FILE>             The file from which input data will be read, if omitted, and the "recursive" option isn't used, input will be read from stdin.
    -k, --key <KEY>                The file containing the key data, or a provided string, against which input will be XOR'd.
                                   This should be larger than the given input data or will need to be repeated to encode the input data.
    -m, --mode <mode>              The operating mode (i.e. whether encrypting or decrypting).
                                   Only applicable when encrypting directories and affects how the file will be renamed.
                                   When in encrypt mode, names are xor'd then converted to hex strings.
                                   When in decrypt mode, names are parsed from hex strings then xor'd to restore the original name. [default: e]  [values: e, d]
    -o, --output <FILE>            The file to which encoded data will be written, if omitted output will be written to stdout.
                                   It's recommended to write output to a file for cases where the encoded data contains non-unicode characters which would otherwise not be printed to the console.
    -r, --recursive <DIRECTORY>    Recursively encrypt / decrypt files and subfolders starting at the given directory.
                                   Files and directory names will be encrypted / decrypted according to the "mode" argument.
                                   Names are xor encrypted then converted to a hex string.
```

## Example usage
The following is an example of encrypting some data and then decrypting it again using the same key

### Encrypt a single file

Original data.
```bash
$ cat lorem_ipsum.txt
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

Encrypt the data using the key "12345".
```bash
$ xor -k "12345" -i lorem_ipsum.txt -o lorem_ipsum.enc
$ cat lorem_ipsum.enc
}]AQX[CG@\W[Y^@G\ERYPEWZ_AVWATFFFPVZD\BQZZRW_]A@QQV\PXG@YZUGQXA]A\_QZP\UG]@DFXTS]AQTFPZ]]AQ\STZTS_]DDS`EVZ\\RP\[]]XDVZ\P_DD[@[^AGF@UVLPCQZ@TE[\ZD^_UXR]XTS]A]F\ZG\GGT][BA\AVLTSWZ\_\PZQ\ZFTCFUAwA\BRAATZF@CWPZ]]A\_AQECW[Q[UWA]A[]C^^FDAPFVCT^Z@TA@QR[_X@\W[Y^@VPDUARXSG[D^_UASA]TEGAtJPQEEWFFB[]@^QPUPRSGVDBZPTESG[^\DG^[WQ[EG@_F][QFXEPBA\]UR\R[RQTAVF@_FYZ]^Z@P\ZYXVQFE_UW^@FY;
```

Decrypt the encrypted data using the same key as before.
```bash
$ xor -k "12345" -i lorem_ipsum.enc -o lorem_ipsum.dec
$ cat lorem_ipsum.dec
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

### Recursively encrypting the contents of a directory

List the directory
```bash
$ ls -R
directory_one
directory_two
example

./directory_one:
child_directory
file_one

./directory_one/child_directory:
file_three

./directory_two:
file_two
```

Recursively encrypt all files and child directories.
```bash
$ xor -k "12345" -r .
$ ls -R
555B415156455D414D6A5E5C56
555B415156455D414D6A45455C

./555B415156455D414D6A5E5C56:
525A5A58516E565A465052465C464C
575B5F516A5E5C56

./555B415156455D414D6A5E5C56/525A5A58516E565A465052465C464C:
575B5F516A455A415150

./555B415156455D414D6A45455C:
575B5F516A45455C
```

Recursively decrypt all files and child directories.
```bash
$ xor -k "12345" -r . -m d
$ ls -R
directory_one
directory_two
example

./directory_one:
child_directory
file_one

./directory_one/child_directory:
file_three

./directory_two:
file_two
```
