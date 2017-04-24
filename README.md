# xor
Command line application that implements basic XOR encryption, written in Rust.

### Installation

If you've not already done so, install rust:
https://www.rust-lang.org/

Then install via cargo with:
```bash
$ cargo install xor
```

### Help
```bash
$ xor --help
xor 1.0.0
Gavyn Riebau
XORs input against a provided key
USAGE:
    xor [OPTIONS] --key <KEY>
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
OPTIONS:
    -i, --input <FILE>    The file from which input data will be read, if omitted input will be read from stdin
    -k, --key <KEY>       The file containing the key against which input will be XOR'd. This should be larger than the given input data or will need to be repeated to encode the input data.
```

### Example usage
The following is an example of encrypting some data and then decrypting it again using the same key

Show the original data:
```bash
$ cat lorem_ipsum.txt
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

Save the key to a file:
```bash
$ echo "12345" > /tmp/key
```

Encrypt the data using the key "12345".
The `2>/dev/null` is used to omit warnings about the key being too small.

```bash
$ xor -k /tmp/key -i lorem_ipsum.txt 2>/dev/null > lorem_ipsum.enc
$ cat lorem_ipsum.enc
}]AQX*XB@AX*U]_[G*B[GTgTFVe_AVWAoEGATnXBZGVc_UQYcEGPnV\PcDA^[Q*EW^DZx[]W\nXVFZA*DFXTh^@VP~V\XZxT^URdPRX\{DS`~W]]X*PVY\dX_BPdXS^{D[@[eBFAAQ*TJVFVcESG]ZdG_XTgR]XTh^@ZGdXAZ@~S_]DXBQM*TSWZg\]W[i^\@QDPFqXAU@~TZF@xTW[YeCZZxTBAQ]o_VVF\~[]Ce]GC@T~TEQYcEVGFoQZXY\W[YeCWQ@*WGT]T~\FXYkBRF\kEGAOIQVDAoD@G\dE\WVkTQR@iDBZPT~PFZZdB
A[\nT\GyD\G\dQFXEkCF]eWTZW\kVVGPxD\GXe]^Z@k_[^\nW@@fPP\F@g8
```

Decrypt the encrypted data using the same key as before.
```bash
$ xor -k /tmp/key -i lorem_ipsum.enc 2>/dev/null > lorem_ipsum.dec
$ cat lorem_ipsum.dec
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugi
at nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```
