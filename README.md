# rxor
Command line application that implements basic XOR encryption, written in Rust.

### Help
```bash
$ rxor --help
rxor 1.0.0
Gavyn Riebau
XORs input against a provided key

USAGE:
    rxor [OPTIONS] --key <KEY>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --input <FILE>    The file from which input data will be read, if omitted input will be read from stdin
    -k, --key <KEY>       The key against which input will be XOR'd. This should be larger than the given input data or will need to be repeated to encode the input data.
```

### Example usage
The following is an example of encrypting some data and then decrypting it again using the same key

Show the original data:
```bash
$ cat lorem_ipsum.txt 
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```
Encrypt the data using the key "12345".
The `2>/dev/null` is used to omit warnings about the key being too small.
```bash
$ rxor -k 12345 -i lorem_ipsum.txt 2>/dev/null 1>lorem_ipsum.enc
$ cat lorem_ipsum.enc 
}]AQX[CG@\W[Y^@G\ERYPEWZ_AVWATFFFPVZD\BQZZRW_]A@QQV\PXG@YZUGQXA]A\_QZP\UG]@DFXTS]AQTFPZ]]AQ\STZTS_]DDS`EVZ\\RP\[]]XDVZ\P_DD[@[^AGF@UVLPCQZ@TE[\ZD^_UXR]XTS]A]F\ZG\GGT][BA\AVLTSWZ\_\PZQ\ZFTCFUAwA\BRAATZF@CWPZ]]A\_AQECW[Q[UWA]A[]C^^FDAPFVCT^Z@TA@QR[_X@\W[Y^@VPDUARXSG[D^_UASA]TEGAtJPQEEWFFB[]@^QPUPRSGVDBZPTESG[^\DG^[WQ[EG@_F][QFXEPBA\]UR\R[RQTAVF@_FYZ]^Z@P\ZYXVQFE_UW^@FY
```
Decrypt the encrypted data using the same key as before.
```bash
$ rxor -k 12345 -i lorem_ipsum.enc 2>/dev/null 1>lorem_ipsum.dec
$ cat lorem_ipsum.dec 
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```
